# Multi-stage: build the Rust binary, then a slim runtime image.
FROM rust:1.95 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Only the CLI is needed to serve requests. Building the whole workspace would
# also pull in the wasm crate and its js-sys/wasm-bindgen dependencies, which
# are of no use in a native image.
RUN cargo build --release -p naksheap-cli --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY --from=build /src/target/release/naksheap /usr/local/bin/naksheap
COPY deploy/server.py /srv/server.py
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin naksheap \
    && mkdir -p /data && chown naksheap:naksheap /data
USER naksheap
ENV NAKSHEAP_BIN=naksheap \
    NAKSHEAP_ARTIFACTS=/data \
    NAKSHEAP_PORT=8080
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["python3", "/srv/server.py"]
