#!/usr/bin/env bash
# Build and run a synthetic Garrett-protocol MWE with the real Rust binaries.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENGINE=${CONTAINER_ENGINE:-docker}
IMAGE=${GARRETT_DEMO_IMAGE:-aivm-secrets-garrett-demo:local}

case "${1:-}" in
    --help|-h)
        cat <<'HELP'
Usage: scripts/garrett-container-demo.sh [--pause]

Build the real native Rust authority, read-only bridge and client into an image,
then run the narrated synthetic-credential demonstration with no external
networking, no bind mounts, a nonroot user, a read-only root filesystem and a
private temporary workspace. The first build downloads Rust/Python dependencies.

Use --pause from an interactive terminal to advance through each explanation.
Set CONTAINER_ENGINE=podman to use Podman rather than Docker.
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
if [ "$#" -gt 1 ]; then
    printf 'Expected at most one argument (try --help).\n' >&2
    exit 2
fi
if [ "${1:-}" = '--pause' ] && { [ ! -t 0 ] || [ ! -t 1 ]; }; then
    printf -- '--pause needs an interactive terminal.\n' >&2
    exit 2
fi

if ! command -v "$ENGINE" >/dev/null 2>&1; then
    printf 'Container engine %s not found; install Docker or set CONTAINER_ENGINE=podman.\n' "$ENGINE" >&2
    exit 2
fi

"$ENGINE" build --file "$ROOT/examples/garrett-demo/Dockerfile" --tag "$IMAGE" "$ROOT"

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
    --pids-limit 128 \
    "$IMAGE" "$@"
