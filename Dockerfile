FROM rust:1.85-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM alpine:3.21
RUN adduser -D -H appuser
COPY --from=builder /src/target/release/netscope /usr/local/bin/netscope
USER appuser
ENTRYPOINT ["netscope"]
