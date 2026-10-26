#!/usr/bin/env bash
# Build and run the synthetic garrett-stateless-v1 walkthrough in a container.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENGINE=${CONTAINER_ENGINE:-docker}
IMAGE=${GARRETT_STATELESS_DEMO_IMAGE:-aivm-secrets-garrett-stateless-demo:local}

case "${1:-}" in
    --help|-h)
        cat <<'HELP'
Usage: scripts/garrett-stateless-demo.sh [--pause]

Build the Rust garrett-stateless binary and the Python package into an image,
then run the narrated walkthrough of Garrett's stateless architecture: agent
certificates, a browser OAuth login through the broker (with a simulated
human and a synthetic identity provider), the bound surrogate, substitution
through the stateless mTLS proxy, a stolen surrogate refused, proxy restart
and a Python replica, and key retirement. No external network at runtime,
nonroot, read-only root filesystem, synthetic credentials only. The first
build downloads the pinned Rust toolchain and Python dependencies.

Use --pause from an interactive terminal to advance step by step.
Set CONTAINER_ENGINE=podman to use Podman.
HELP
        exit 0
        ;;
    ''|--pause)
        ;;
    *)
        printf 'Unsupported argument: %s (try --help)\n' "$1" >&2
        exit 2
        ;;
esac
if [ "${1:-}" = '--pause' ] && { [ ! -t 0 ] || [ ! -t 1 ]; }; then
    printf -- '--pause needs an interactive terminal.\n' >&2
    exit 2
fi
if ! command -v "$ENGINE" >/dev/null 2>&1; then
    printf 'Container engine %s not found; install Docker or set CONTAINER_ENGINE=podman.\n' "$ENGINE" >&2
    exit 2
fi

"$ENGINE" build --file "$ROOT/examples/garrett-stateless/Dockerfile" --tag "$IMAGE" "$ROOT"

TTY_OPT=()
if [ -t 0 ] && [ -t 1 ]; then
    TTY_OPT=(-t)
fi
"$ENGINE" run --rm -i "${TTY_OPT[@]}" \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 256 \
    "$IMAGE" "$@"
