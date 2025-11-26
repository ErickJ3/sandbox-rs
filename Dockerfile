FROM rust:1.91-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/main.rs

RUN cargo build --release && \
    rm -rf src
COPY src ./src
COPY examples ./examples

RUN touch src/lib.rs src/bin/main.rs && \
    cargo build --release --bin sandbox-ctl

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/sandbox-ctl /usr/local/bin/sandbox-ctl
RUN mkdir -p /sandbox/workdir /sandbox/volumes

WORKDIR /sandbox
ENTRYPOINT ["/usr/local/bin/sandbox-ctl"]
CMD ["--help"]
