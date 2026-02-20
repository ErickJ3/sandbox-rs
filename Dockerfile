FROM rust:1.91-bookworm AS builder

WORKDIR /build

# Copy workspace sources
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY sandbox-ctl ./sandbox-ctl

RUN cargo build --release --locked --package sandbox-ctl

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/sandbox-ctl /usr/local/bin/sandbox-ctl

RUN useradd --create-home sandbox
USER sandbox

WORKDIR /home/sandbox
ENTRYPOINT ["/usr/local/bin/sandbox-ctl"]
CMD ["--help"]
