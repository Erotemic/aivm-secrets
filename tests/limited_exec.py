"""Test-only launch supervisor: exec a program with deterministic file-I/O failure.

No provider credentials are passed to this helper. Ignoring SIGXFSZ lets the
Rust program receive EFBIG and exercise its ordinary error handling.
"""

import os
import resource
import signal
import sys

if __name__ == "__main__":
    limit = int(sys.argv[1])
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    os.execv(sys.argv[2], sys.argv[2:])
