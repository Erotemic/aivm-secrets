"""Security mutation testing: change one security check in the Rust crate,
re-extract it, and require the unchanged Lean proofs to reject the result.

    python verification/mutate.py [--filter REGEX] [--jobs N]

Each mutant gets its own copy of ``crates/garrett-stateless-core`` and its
own Lean output directory; it recompiles the generated module and then the
whole local import closure of the proof module mapped to it (``PROOFS``,
``MUTANT_PROOFS``), never substituting a cached object. A mutant counts as
rejected only when that closure fails with a Lean error; a timeout, a
missing module or a resource limit aborts the run instead.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import extract
import toolchain
from toolchain import LEAN, PROOFS, ROOT, run

CORE = ROOT / 'crates' / extract.CRATE
# The proof module that must reject a mutant of each source file.
PROOFS_BY_FILE = {
    'stateless.rs': 'GarrettStateless',
    'stateless_login.rs': 'GarrettStatelessLogin',
    'stateless_mailbox.rs': 'GarrettStatelessMailbox',
    'stateless_proxy.rs': 'GarrettStatelessConnection',
    'stateless_token.rs': 'GarrettStatelessProtocol',
    'stateless_policy.rs': 'GarrettStatelessComposition',
}
# Mutants whose defect is rejected by a module outside their file's default.
MUTANT_PROOFS = {
    'stateless state login label not bound': 'GarrettStatelessState',
    # The strict profile's theorem: no login provider, no login state.
    'stateless login started for an unconfigured provider': 'GarrettStatelessStrict',
    # The composition theorem and its read-only instantiation.
    'stateless proxy operation policy not consulted': 'GarrettStatelessComposition',
    'stateless proxy credential decrypted before authorization': 'GarrettStatelessComposition',
}

MUTANTS = [
    ("stateless.rs", "stateless certificate binding removed", "if !(certificate == peer) {", "if false {"),
    ("stateless.rs", "stateless expired token accepted", "if now >= claims.expires_at {", "if now > claims.expires_at {"),
    ("stateless.rs", "stateless audience not checked", "if !member(&acceptance.audiences, &claims.audience) {",
     "if false {"),
    ("stateless.rs", "stateless verifying key issuer not checked", "if !(issuer == key_issuer) {", "if false {"),
    ("stateless.rs", "stateless decrypted before admission",
     "    match admit(\n        &verified.claims,\n        &verified.key_issuer,\n        acceptance,\n        peer,\n        now,\n    ) {\n        Ok(()) => (),\n        Err(error) => return Err(error),\n    }\n"
     "    let credential = match opener.unseal(&verified) {\n        Ok(credential) => credential,\n        Err(error) => return Err(error),\n    };\n",
     "    let credential = match opener.unseal(&verified) {\n        Ok(credential) => credential,\n        Err(error) => return Err(error),\n    };\n"
     "    match admit(\n        &verified.claims,\n        &verified.key_issuer,\n        acceptance,\n        peer,\n        now,\n    ) {\n        Ok(()) => (),\n        Err(error) => return Err(error),\n    }\n"),
    ("stateless.rs", "stateless issuance binds the wrong certificate", "        certificate: grant.certificate,\n",
     "        certificate: token_id.to_vec(),\n"),
    ("stateless.rs", "stateless renewal extends ren", "        credential_expires: claims.renew_until,\n",
     "        credential_expires: MAX_TIME,\n"),
    ("stateless_login.rs", "stateless login binds a request value instead of the peer",
     "        certificate: peer.to_vec(),\n", "        certificate: subject.to_vec(),\n"),
    ("stateless_login.rs", "stateless login callback state not checked",
     "    if !same_login(policy, entry, state) {\n        return Err(LoginDenial::Invalid);",
     "    if false {\n        return Err(LoginDenial::Invalid);"),
    ("stateless_login.rs", "stateless login delivered to any peer", "if !(certificate == peer) {", "if false {"),
    ("stateless_proxy.rs", "stateless proxy wrong provider destination",
     "let index = route_of(routes, &verified.claims.provider);", "let index: usize = 0;"),
    ("stateless_proxy.rs", "stateless proxy egress without acknowledged admission",
     "if !origin.admitted(&opened.claims, index) {", "if false {"),
    ("stateless_proxy.rs", "stateless proxy surrogate forwarded instead of credential",
     "        &opened.credential,\n        &route.authentication,", "        &token,\n        &route.authentication,"),
    ("stateless_proxy.rs", "stateless proxy credential reflection unchecked",
     "let forms = reflection_forms(&opened.credential);", "let forms = reflection_forms(b\"\");"),
    ("stateless_proxy.rs", "stateless proxy dispatches despite an encoder refusal",
     "Err(refusal) => Decision::Refused(code_of(&refusal)),",
     "Err(_refusal) => Decision::Dispatch(Dispatch {\n            route: index,\n            wire,\n            opened,\n        }),"),
    # Operation authorization (GarrettStatelessComposition): removing or
    # bypassing the policy, or weakening the read-only policy.
    ("stateless_proxy.rs", "stateless proxy operation policy not consulted",
     "if !policy.permits(&verified.claims, &operation_of(request)) {", "if false {"),
    ("stateless_proxy.rs", "stateless proxy credential decrypted before authorization",
     "    if !policy.permits(&verified.claims, &operation_of(request)) {\n"
     "        return Decision::Refused(Code::Denied);\n    }\n"
     "    let opened = match stateless::decrypt(opener, verified) {\n"
     "        Ok(opened) => opened,\n        Err(rejection) => return Decision::Unauthorized(Some(rejection)),\n    };\n",
     "    let claims = stateless::authenticate(opener, &token, acceptance, peer, now);\n"
     "    let opened = match stateless::decrypt(opener, verified) {\n"
     "        Ok(opened) => opened,\n        Err(rejection) => return Decision::Unauthorized(Some(rejection)),\n    };\n"
     "    let permitted = match claims {\n        Ok(v) => policy.permits(&v.claims, &operation_of(request)),\n"
     "        Err(_) => false,\n    };\n"
     "    if !permitted {\n        return Decision::Refused(Code::Denied);\n    }\n"),
    ("stateless_policy.rs", "stateless read-only policy permits a write method",
     "        read_method(&operation.method)\n", "        true\n"),
    ("stateless_policy.rs", "stateless read-only policy permits a body",
     "            && operation.body == 0\n", "            && true\n"),
    ("stateless_policy.rs", "stateless read-only policy ignores the destination provider",
     "    own == provider\n", "    true\n"),
    ("stateless_policy.rs", "stateless read-only policy ignores the resource path",
     "        && path_matches(&resource.path, &operation.path)\n", "        && true\n"),
    ("stateless_policy.rs", "stateless read-only policy ignores the resource method",
     "        && method_ok(&resource.method, &operation.method)\n", "        && true\n"),
    ("stateless_policy.rs", "stateless operation path includes the query",
     "        path: request.target[..end].to_vec(),\n", "        path: request.target.clone(),\n"),
    ("stateless_login.rs", "stateless login started for an unconfigured provider",
     "if !stateless::member(&policy.providers, provider) {", "if false {"),
    ("stateless_mailbox.rs", "stateless mailbox duplicate login accepted",
     "if find(&mailbox.slots, &state.login) < mailbox.slots.len() {", "if false {"),
    ("stateless_mailbox.rs", "stateless mailbox serial reused", "        serial: mailbox.next,\n", "        serial: 0,\n"),
    ("stateless_mailbox.rs", "stateless mailbox capacity not enforced", "if live(&mailbox.slots) >= MAX_PENDING {",
     "if false {"),
    ("stateless_mailbox.rs", "stateless mailbox exchange answer reaches another login",
     "if slot.serial != exchanged.permit.serial {", "if false {"),
    ("stateless_mailbox.rs", "stateless mailbox finish ignores the stage",
     "            match slot.entry.stage {\n                Stage::Exchanging => (),\n                _ => return Err(MailboxError::Consumed),\n            }\n            let result",
     "            let result"),
    ("stateless_mailbox.rs", "stateless mailbox poll ignores the peer",
     "Some(slot) => stateless_login::deliver(&slot.entry, peer, now),",
     "Some(slot) => stateless_login::deliver(&slot.entry, &slot.entry.certificate, now),"),
    ("stateless_proxy.rs", "stateless proxy connection decides for the authority, not the peer",
     "                peer,\n                now,\n                limit,\n",
     "                authority,\n                now,\n                limit,\n"),
    ("stateless_token.rs", "stateless token kid not used to select the key",
     "while index < entries.len() && !named(&entries[index], kid) {",
     "while false && !named(&entries[index], kid) {"),
    ("stateless_token.rs", "stateless token duplicate kid accepted in a key set",
     "&& select(entries, &entry.kid) == index", "&& true"),
    ("stateless_token.rs", "stateless token associated data omits the header",
     "    append(&mut aad, header);", "    let _ = header;"),
    ("stateless_token.rs", "stateless token payload with trailing bytes accepted",
     "if i + 1 != bytes.len() {", "if i + 1 > bytes.len() {"),
    ("stateless_token.rs", "stateless token signature checked over the payload only",
     "if !entry.material.verify(&token[..second], &signature) {",
     "if !entry.material.verify(&token[first + 1..second], &signature) {"),
    ("stateless_token.rs", "stateless token decrypted with the first key",
     "    match entries[verified.key]", "    match entries[0]"),
    ("stateless_token.rs", "stateless token credential allowed in the public payload",
     "if occurs(&header, credential) || occurs(&public, credential) {", "if occurs(&header, credential) {"),
    ("stateless_token.rs", "stateless token header prefix not checked",
     "if start != HEADER_START || ending != HEADER_END {", "if ending != HEADER_END {"),
    ("stateless_token.rs", "stateless token non-canonical base64 accepted",
     "    if same != text {", "    if false && same != text {"),
    ("stateless_token.rs", "stateless token provider grammar not checked",
     "        && is_provider(&claims.provider)\n", "\n"),
    ("stateless_token.rs", "stateless state login label not bound",
     "let ciphertext = match key.seal(nonce, LOGIN_LABEL, &state_bytes(state)) {",
     "let ciphertext = match key.seal(nonce, CREDENTIAL_LABEL, &state_bytes(state)) {"),
]


def closure(module: str) -> list[str]:
    """`module` and the local proof modules it imports, dependencies first."""
    order: list[str] = []
    seen: set[str] = set()

    def visit(name: str) -> None:
        if name in seen:
            return
        seen.add(name)
        for imported in re.findall(r'(?m)^import ([A-Za-z0-9_]+)$', (PROOFS / f'{name}.lean').read_text()):
            if (PROOFS / f'{imported}.lean').is_file():
                visit(imported)
        order.append(name)

    visit(module)
    return order


def check(mutant: tuple[str, str, str, str], lean_path: str) -> str:
    file, label, old, new = mutant
    source = CORE / 'src' / file
    if source.read_text().count(old) != 1:
        raise SystemExit(f'mutation no longer matches once: {label}')
    with tempfile.TemporaryDirectory(prefix='garrett-mutant-', dir=ROOT / '.tools') as scratch:
        temporary = Path(scratch)
        workspace = temporary / 'workspace'
        shutil.copytree(CORE, workspace / 'crates' / extract.CRATE, ignore=shutil.ignore_patterns('target'))
        shutil.copy2(ROOT / 'rust-toolchain.toml', workspace / 'rust-toolchain.toml')
        (workspace / 'Cargo.toml').write_text(
            f'[workspace]\nmembers=["crates/{extract.CRATE}"]\nresolver="2"\n[workspace.package]\n'
            'version="0.1.0"\nedition="2021"\nlicense="Apache-2.0"\n')
        (workspace / 'Cargo.lock').write_text(f'version = 4\n[[package]]\nname="{extract.CRATE}"\nversion="0.1.0"\n')
        target = workspace / 'crates' / extract.CRATE / 'src' / file
        target.write_text(source.read_text().replace(old, new))
        extract.extract(temporary, workspace, quiet=True)
        lean = [toolchain.executable('elan'), 'run', LEAN, 'lean', '-DwarningAsError=true']
        env = dict(os.environ, LEAN_PATH=str(temporary) + os.pathsep + lean_path)
        generated = temporary / extract.MODULE
        built = subprocess_run([*lean, '-o', generated.with_suffix('.olean'), generated], temporary, env)
        if built.returncode != 0:
            raise SystemExit(f'the mutated extraction does not compile: {label}\n{built.stdout}')
        for module in closure(MUTANT_PROOFS.get(label, PROOFS_BY_FILE[file])):
            proof = temporary / f'{module}.lean'
            shutil.copy2(PROOFS / proof.name, proof)
            result = subprocess_run([*lean, '-DmaxErrors=1', '-o', temporary / f'{module}.olean', proof],
                                    temporary, env)
            if result.returncode == 0:
                continue
            output = result.stdout + result.stderr
            infrastructure = any(x in result.stdout for x in ['unknown module prefix', 'does not exist',
                                                                 'cannot find file'])
            resources = any(x in output.lower() for x in ['timeout', 'heartbeats', 'maximum recursion depth',
                                                          'out of memory', 'stack overflow', 'interrupted'])
            if infrastructure or resources or not re.search(rf'{module}\.lean:\d+:\d+: error:', result.stdout):
                raise SystemExit(f'mutant failed for an unexpected reason: {label}\n{output}')
            return f'Lean rejected re-extracted Rust mutation: {label} ({module})'
        raise SystemExit(f'mutant survived the proofs: {label}')


def subprocess_run(argv, cwd: Path, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run([str(a) for a in argv], cwd=cwd, env=env, capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--filter', help='run only labels matching this regex (not the full campaign)')
    parser.add_argument('--jobs', type=int, default=min(4, os.cpu_count() or 1), help='mutants checked at once')
    args = parser.parse_args()
    # The proofs are about the committed extraction; it must match the source.
    with tempfile.TemporaryDirectory(prefix='garrett-extract-', dir=ROOT / '.tools') as scratch:
        if extract.extract(Path(scratch), quiet=True).read_bytes() != (PROOFS / 'generated' / extract.MODULE).read_bytes():
            raise SystemExit('proofs/generated is stale: run verification/extract.py write first')
    run([toolchain.executable('lake'), 'build'], cwd=PROOFS)
    selected = [m for m in MUTANTS if args.filter is None or re.search(args.filter, m[1])]
    if not selected:
        raise SystemExit('no mutants match the filter')
    print(f'Selected {len(selected)} of {len(MUTANTS)} security mutations; filter={args.filter!r}', flush=True)
    lean_path = run([toolchain.executable('lake'), 'env', 'printenv', 'LEAN_PATH'], cwd=PROOFS, capture=True,
                    quiet=True).stdout.strip()
    lean_path = os.pathsep.join(str((PROOFS / part).resolve()) for part in lean_path.split(os.pathsep))
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(check, m, lean_path) for m in selected]
        try:
            for done, future in enumerate(as_completed(futures), 1):
                print(f'[{done}/{len(selected)}] {future.result()}', flush=True)
        except BaseException:
            # Stop at the first failure instead of finishing the queue.
            pool.shutdown(cancel_futures=True)
            raise
    print(f'All {len(selected)} selected mutants were rejected.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
