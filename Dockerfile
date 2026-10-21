# Multi-stage container build for Velenza Inarch (`inr`)
# Zero external Rust crate dependencies — builds in seconds from pure `std`.
FROM rust:1-trixie AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --bin inr

FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /var/lib/inarch inarch \
    && mkdir -p /var/lib/inarch/store /var/lib/inarch/cache/t1 /var/lib/inarch/cache/t2 /etc/inarch \
    && chown -R inarch:inarch /var/lib/inarch /etc/inarch

COPY --from=builder /src/target/release/inr /usr/local/bin/inr
COPY deploy/server.example.toml /etc/inarch/inarch.toml

USER inarch
WORKDIR /var/lib/inarch

EXPOSE 7331

ENTRYPOINT ["/usr/local/bin/inr"]
CMD ["--config", "/etc/inarch/inarch.toml", "serve", "--listen", "0.0.0.0:7331"]
