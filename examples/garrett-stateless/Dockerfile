# A functional garrett-stateless-v1 demonstration, not a VM/TPM isolation proof.
# Stage 1 builds the real Rust broker/proxy/agent CLI with the pinned toolchain.
FROM rust:1-bookworm AS native
WORKDIR /source
RUN rustup toolchain install nightly-2026-09-17 --profile minimal
COPY rust/ ./rust/
RUN cargo +nightly-2026-09-17 build --release --locked \
    --manifest-path rust/Cargo.toml -p garrett-stateless --bin garrett-stateless

# Stage 2: the Python package (same CLI, independent implementation), the
# Rust binary and the synthetic provider fixture. No real credentials.
FROM python:3.13-slim-bookworm
COPY pyproject.toml README.md LICENSE /src/
COPY aivm_secrets/ /src/aivm_secrets/
RUN python -m pip install --no-cache-dir cryptography==46.0.4 \
    && python -m pip install --no-cache-dir --no-deps /src \
    && rm -rf /src \
    && groupadd --gid 10001 demo \
    && useradd --uid 10001 --gid 10001 --no-create-home demo
COPY examples/garrett-stateless/walkthrough.py examples/garrett-stateless/synthetic_provider.py /opt/garrett-stateless/
COPY --from=native /source/rust/target/release/garrett-stateless /usr/local/bin/garrett-stateless-native
ENV PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["python", "/opt/garrett-stateless/walkthrough.py", "--rust", "/usr/local/bin/garrett-stateless-native", "--python-cmd", "python -m aivm_secrets.garrett_stateless"]
