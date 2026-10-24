#!/usr/bin/env python3
"""Opt-in real-VM check of the certificate-bound identity lifecycle.

Drives `aivm vm identity_*` against an existing managed AIVM VM with a fresh,
temporary identity authority, and checks each step against the authority's
own `identity status`, never against AIVM's word:

1. enroll; with `--yes_sudo` but without `--yes` and without a terminal,
   `enroll --replace` is refused because it is an operator-only verb;
2. renew; rotate the guest key; renew again, which must certify the rotated
   key, not the rotated-away one;
3. shut the VM down and start it; renewal still works;
4. restore the guest's identity files from before a rotation (a guest
   snapshot restore): renewal is refused and the registry is unchanged; the
   restored, retired key cannot be enrolled again; removing the guest's
   identity and re-enrolling with `--replace` (a compare-and-swap) recovers;
5. hide `openssl` in the guest: renewal fails before anything is issued;
6. revoke: renewal is refused; `identity verify` reports a clean authority.

It uses no provider credential and changes nothing outside the temporary
authority, the guest's `~/.config/aivm/identity` and, briefly, the guest's
`/usr/bin/openssl` name. Run it only on a disposable VM you may modify. The
AIVM SSH host key must already be pinned (`aivm vm access reconcile`), and
the VM must be AIVM's active VM.

    python dev/aivm_identity_lifecycle_acceptance.py --vm aivm-2404
"""
from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class Failure(Exception):
    pass


class Lifecycle:
    def __init__(self, vm: str, root: Path, aivm: str, python: str):
        self.vm, self.root, self.aivm, self.python = vm, root, aivm, python
        self.steps: dict[str, object] = {}
        self.last = ''

    def run(self, argv: list[str], *, stdin: bytes | None = b'', timeout: int = 600):
        result = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
        if argv[:2] == [self.aivm, 'vm'] and argv[2].startswith('identity'):
            # Kept for the failure report: AIVM's log of the last identity step.
            self.last = (b' '.join(a.encode() for a in argv[2:3])
                         + b': ' + result.stderr[-600:]).decode('utf-8', 'replace')
        return result

    def identity(self, *words: str) -> dict:
        result = self.run([self.python, '-I', '-m', 'aivm_secrets', 'identity', *words,
                           '--root', str(self.root)])
        if result.returncode:
            raise Failure(f'identity {words[0]} failed')
        return json.loads(result.stdout)

    def row(self) -> dict:
        subjects = self.identity('status')['subjects']
        if len(subjects) != 1:
            raise Failure('expected exactly one enrolled subject')
        return next(iter(subjects.values()))

    def vm_identity(self, action: str, *extra: str, yes: bool = True) -> subprocess.CompletedProcess:
        argv = [self.aivm, 'vm', action, '--vm', self.vm, '--identity_root', str(self.root), *extra]
        # Without --yes, pass --yes_sudo: it skips every ordinary confirmation
        # and must still not skip an operator-only verb.
        return self.run(argv + (['--yes'] if yes else ['--yes_sudo']), stdin=None if yes else b'')

    def guest(self, script: str) -> subprocess.CompletedProcess:
        # `aivm vm ssh_config` describes the active VM; run this with --vm set
        # to the active VM.
        config = self.run([self.aivm, 'vm', 'ssh_config']).stdout.decode()
        host = next(line.split()[1] for line in config.splitlines()
                    if line.strip().startswith('HostName'))
        key = next(line.split()[1] for line in config.splitlines()
                   if line.strip().startswith('IdentityFile'))
        user = next(line.split()[1] for line in config.splitlines()
                    if line.strip().startswith('User'))
        return self.run(['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes',
                         '-o', 'StrictHostKeyChecking=accept-new', '-i', key,
                         f'{user}@{host}', script])

    def expect(self, ok: bool, label: str) -> None:
        if not ok:
            raise Failure(label)
        self.steps[label] = True

    def check(self) -> dict:
        enrolled = self.vm_identity('identity_enroll')
        self.expect(enrolled.returncode == 0 and self.row()['epoch'] == 0, 'enrolled')
        refused = self.vm_identity('identity_enroll', '--replace', yes=False)
        self.expect(refused.returncode != 0 and b'operator-only' in refused.stderr + refused.stdout
                    and self.row()['epoch'] == 0, 'replace_without_yes_refused')

        self.expect(self.vm_identity('identity_renew').returncode == 0
                    and self.row()['epoch'] == 1, 'renewed')
        before = self.row()['key_sha256']
        self.guest('rm -rf ~/.aivm-id-backup && cp -a ~/.config/aivm/identity ~/.aivm-id-backup')
        self.expect(self.vm_identity('identity_rotate_key').returncode == 0
                    and self.row()['key_sha256'] != before, 'key_rotated')
        rotated = self.row()['key_sha256']
        self.expect(self.vm_identity('identity_renew').returncode == 0
                    and self.row()['key_sha256'] == rotated, 'renewal_after_rotation_keeps_new_key')

        down = self.run([self.aivm, 'vm', 'down', '--yes', '--yes_sudo'])
        # A graceful shutdown can still be in progress when `down` returns;
        # starting then would find the domain running and do nothing.
        for _ in range(60):
            state = self.run([self.aivm, 'vm', 'status', '--yes_sudo']).stdout
            if b'state=running' not in state:
                break
            time.sleep(5)
        up = self.run([self.aivm, 'vm', 'up', '--yes', '--yes_sudo'], timeout=900)
        self.run([self.aivm, 'vm', 'wait_ip', '--yes', '--yes_sudo'])
        # An address comes before sshd; wait until the guest answers.
        for _ in range(60):
            if self.guest('true').returncode == 0:
                break
            time.sleep(5)
        epoch = self.row()['epoch']
        self.expect(down.returncode == 0 and up.returncode == 0
                    and self.vm_identity('identity_renew').returncode == 0
                    and self.row()['epoch'] == epoch + 1, 'renewal_after_restart')

        # The backup lives in the guest's home: /tmp does not survive the
        # restart above.
        restored = self.guest('rm -rf ~/.config/aivm/identity && '
                              'cp -a ~/.aivm-id-backup ~/.config/aivm/identity')
        self.expect(restored.returncode == 0, 'guest_identity_restored_from_backup')
        epoch = self.row()['epoch']
        self.expect(self.vm_identity('identity_renew').returncode != 0
                    and self.row()['epoch'] == epoch, 'restored_guest_cannot_renew')
        self.expect(self.vm_identity('identity_enroll', '--replace').returncode != 0
                    and self.row()['epoch'] == epoch, 'retired_key_cannot_be_reenrolled')
        self.guest('rm -rf ~/.config/aivm/identity ~/.aivm-id-backup')
        self.expect(self.vm_identity('identity_enroll', '--replace').returncode == 0
                    and self.row()['epoch'] == epoch + 1
                    and self.row()['key_sha256'] not in (before, rotated), 'recovered_with_fresh_key')

        epoch = self.row()['epoch']
        self.guest('sudo -n mv /usr/bin/openssl /usr/bin/openssl.aivm-hidden')
        try:
            failed = self.vm_identity('identity_renew')
        finally:
            self.guest('sudo -n mv /usr/bin/openssl.aivm-hidden /usr/bin/openssl')
        self.expect(failed.returncode != 0 and self.row()['epoch'] == epoch,
                    'missing_guest_openssl_issues_nothing')

        subject = next(iter(self.identity('status')['subjects']))
        self.identity('revoke', '--subject', subject)
        self.expect(self.vm_identity('identity_renew').returncode != 0
                    and self.row()['active'] is False, 'revoked_identity_cannot_renew')
        self.expect(self.identity('verify')['clean'] is True, 'authority_verifies_clean')
        return {'ok': True, 'vm': self.vm, 'steps': self.steps}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', default='aivm-2404')
    parser.add_argument('--aivm', default=shutil.which('aivm') or 'aivm')
    parser.add_argument('--python', default=sys.executable,
                        help='interpreter that can import aivm_secrets')
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix='aivm-identity-') as temporary:
        root = Path(temporary) / 'authority'
        init = subprocess.run([args.python, '-I', '-m', 'aivm_secrets', 'identity', 'init',
                               '--root', str(root)], capture_output=True)
        if init.returncode:
            print('could not initialize a temporary identity authority', file=sys.stderr)
            return 1
        lifecycle = Lifecycle(args.vm, root, args.aivm, args.python)
        try:
            report = lifecycle.check()
        except Failure as failure:
            print(json.dumps({'ok': False, 'failed_at': str(failure),
                              'passed': lifecycle.steps,
                              'last_identity_step': lifecycle.last}, indent=2))
            return 1
        finally:
            lifecycle.guest('rm -rf ~/.config/aivm/identity ~/.aivm-id-backup')
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
