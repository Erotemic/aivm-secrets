# The image is a functional protocol demo, not a VM / TPM / OS-isolation proof.
# This stage builds the actual, pinned-toolchain production Rust executables.
FROM rust:1-bookworm AS native
WORKDIR /source
RUN rustup toolchain install nightly-2026-09-17 --profile minimal
COPY rust/ ./rust/
RUN cargo +nightly-2026-09-17 build --release --locked \
    --manifest-path rust/Cargo.toml \
    -p aivm-secrets-garrett \
    --bin garrett-authority \
    --bin garrett-bridge-read-only \
    --bin garrett-client

# The runtime intentionally contains no cargo, Docker socket, KVM, provider
# credentials or external provider client. All credentials are synthetic.
FROM python:3.13-slim-bookworm
RUN python -m pip install --no-cache-dir cryptography==46.0.4 \
    && groupadd --gid 10001 demo \
    && useradd --uid 10001 --gid 10001 --no-create-home demo
WORKDIR /opt/aivm-secrets
COPY aivm_secrets/ ./aivm_secrets/
COPY dev/offline_native_guest.py ./dev/offline_native_guest.py
COPY --from=native /source/rust/target/release/garrett-authority /usr/local/bin/garrett-authority
# Install the *read-only* binary under the demo's canonical bridge name.
COPY --from=native /source/rust/target/release/garrett-bridge-read-only /usr/local/bin/garrett-bridge
COPY --from=native /source/rust/target/release/garrett-client /usr/local/bin/garrett-client
ENV PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["python", "/opt/aivm-secrets/dev/offline_native_guest.py", "--bin-dir", "/usr/local/bin", "--walkthrough"]
