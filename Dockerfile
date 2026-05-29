# syntax=docker/dockerfile:1

FROM --platform=linux/amd64 lukemathwalker/cargo-chef:latest-rust-1.86 AS chef
WORKDIR /build

# ── Planner: compute the dependency recipe ──────────────────────────────────
FROM chef AS planner
COPY Cargo.toml Cargo.toml
COPY crypto/    crypto/
COPY web/       web/
RUN cargo chef prepare --recipe-path recipe.json

# ── Builder: cache deps, then compile ───────────────────────────────────────
FROM chef AS builder

# Restore the recipe and cook deps only (cached unless Cargo.toml changes)
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy full source and do the real build
COPY Cargo.toml Cargo.toml
COPY crypto/    crypto/
COPY web/       web/
RUN cargo build --release --bin web

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM --platform=linux/amd64 debian:bookworm-slim
RUN apt update && apt install -y openssl
COPY --from=builder /build/target/release/web /usr/local/bin/web
EXPOSE 3000
CMD ["/usr/local/bin/web"]
