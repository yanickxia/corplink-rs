# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25.5
ARG RUST_VERSION=1.96.0

FROM golang:${GO_VERSION}-bookworm AS wireguard-build
ARG TARGETARCH
WORKDIR /src/wireguard-go
COPY libwg/wireguard-go/go.mod libwg/wireguard-go/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked go mod download
COPY libwg/wireguard-go/ ./
# The build context deliberately excludes Git metadata and host-generated files.
# Build the checked-out submodule, without fetching a moving branch during build.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=corplink-go-${TARGETARCH},target=/root/.cache/go-build \
    printf 'package main\n\nconst Version = "corplink-rs-dev (container)"\n' > libwg/version.go \
    && mkdir /out \
    && CGO_ENABLED=1 go build -mod=readonly -buildvcs=false -trimpath \
        -buildmode=c-archive -o /out/libwg.a ./libwg

FROM rust:${RUST_VERSION}-bookworm AS rust-build
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends libclang-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src/corplink-rs
COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ src/
COPY --from=wireguard-build /out/libwg.a /out/libwg.h ./libwg/
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=corplink-rust-${TARGETARCH},target=/src/corplink-rs/target,sharing=locked \
    cargo build --release --locked \
    && install -D target/release/corplink-rs /out/corplink-rs-dev

# Optional Linux regression suite: docker build --target test .
FROM rust-build AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=corplink-rust-${TARGETARCH},target=/src/corplink-rs/target,sharing=locked \
    cargo test --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 libgcc-s1 tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 corplink \
    && useradd --uid 10001 --gid corplink --home-dir /config --no-create-home corplink \
    && install -d -o corplink -g corplink /config
COPY --from=rust-build /out/corplink-rs-dev /usr/local/bin/corplink-rs-dev
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/corplink-entrypoint
ENV RUST_LOG=info
WORKDIR /config
USER 10001:10001
EXPOSE 1080/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/corplink-entrypoint"]
CMD ["/config/config.json"]
