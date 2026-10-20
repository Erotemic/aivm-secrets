"""Small, diagnostic subprocess boundary for focused Lean verification.

Kernel and axiom checks remain the callers' responsibility. In particular, a
quiet compiler exit must never be mistaken for a successful proof.
"""
from __future__ import annotations

import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path


class LeanStepError(RuntimeError):
    """A toolchain invocation failed or was terminated before checking a proof."""


def _output(label: str, value: str) -> str:
    if not value:
        return f'{label}: (empty)'
    # Keep the useful end of a potentially verbose compiler log in the error.
    limit = 24_000
    if len(value) > limit:
        return f'{label}: (first {len(value) - limit} characters omitted)\n{value[-limit:]}'
    return f'{label}:\n{value}'


def run(command: list[str], cwd: Path, label: str) -> str:
    """Run a focused proof stage and report signal, exit code and diagnostics.

    Do not add a timeout or a fallback-to-source-review here: a full kernel
    check has to finish successfully to count as proof verification.
    """
    rendered = shlex.join(map(str, command))
    print(f'[Lean] {label}: {rendered}', file=sys.stderr, flush=True)
    start = time.monotonic()
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    except OSError as exc:
        raise LeanStepError(f'{label}: could not start {rendered} '
                            f'(cwd={cwd}): {exc}') from exc
    seconds = time.monotonic() - start
    if result.returncode != 0:
        if result.returncode < 0:
            signum = -result.returncode
            try:
                signame = signal.Signals(signum).name
            except ValueError:
                signame = f'unknown signal {signum}'
            status = f'terminated by {signame} ({signum})'
        else:
            status = f'exited with code {result.returncode}'
        hint = ''
        if result.returncode == -signal.SIGKILL:
            hint = ('\nSIGKILL may indicate an out-of-memory kill or an external '
                    'termination. Check `journalctl -k -n 100` and available '
                    'RAM/swap before modifying the Lean theorems.')
        raise LeanStepError(
            f'{label}: {status} after {seconds:.1f}s\n'
            f'command: {rendered}\ncwd: {cwd}\n'
            f'{_output("stdout", result.stdout)}\n'
            f'{_output("stderr", result.stderr)}{hint}'
        )
    print(f'[Lean] {label}: passed in {seconds:.1f}s', file=sys.stderr, flush=True)
    return result.stdout + '\n' + result.stderr
