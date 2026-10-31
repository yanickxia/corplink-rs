FROM golang:1.25.5-alpine3.22@sha256:3587db7cc96576822c606d119729370dbf581931c5f43ac6d3fa03ab4ed85a10 AS golang
FROM rust:1.96.0-alpine3.22@sha256:8c6ab6493f2e93ee7c21781bc599a7e07278aceb15fefb968144d7e4cf8c9a04 AS build
RUN apk add --no-cache build-base clang-dev openssl-dev openssl-libs-static pkgconf linux-headers file binutils
COPY --from=golang /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2 CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true RUSTC_WRAPPER=/work/rustc-build-tools.sh OPENSSL_STATIC=1 OPENSSL_LIB_DIR=/usr/lib OPENSSL_INCLUDE_DIR=/usr/include
WORKDIR /work
COPY musl-go-init.c adapt-musl-go.sh rustc-build-tools.sh ./
RUN chmod +x /work/*.sh
COPY source/libwg /work/src/libwg
WORKDIR /work/src/libwg/wireguard-go
RUN printf 'package main\nconst Version = "corplink-rs-dev a73b9f07989a (LuCI)"\n' > libwg/version.go && CGO_ENABLED=1 go build -mod=readonly -buildvcs=false -trimpath -buildmode=c-archive -o ../libwg.a ./libwg && go test -mod=readonly ./libwg ./conn
RUN sh /work/adapt-musl-go.sh
WORKDIR /work/src
COPY source/Cargo.toml source/Cargo.lock source/build.rs ./
COPY source/vendor ./vendor
COPY source/.cargo ./.cargo
COPY source/src ./src
RUN cargo build --release --locked && cargo test --release --locked -- --test-threads=2
RUN mkdir -p /out && install -m 755 target/release/corplink-rs /out/corplink-rs-dev && strip --strip-debug /out/corplink-rs-dev && file /out/corplink-rs-dev && sha256sum /out/corplink-rs-dev
FROM scratch AS artifact
COPY --from=build /out/ /
