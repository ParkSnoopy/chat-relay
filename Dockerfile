FROM rust:1-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked

FROM debian:bookworm-slim

COPY --from=builder --chown=65532:65532 /build/target/debug/chat-relay /usr/local/bin/chat-relay

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/chat-relay"]
