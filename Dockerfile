# syntax=docker/dockerfile:1

FROM rust:1.88-slim AS builder
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/api-scanner /usr/local/bin/api-scanner
COPY --from=builder /app/assets /assets

WORKDIR /work
ENTRYPOINT ["api-scanner"]
