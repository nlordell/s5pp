FROM rust:bullseye AS build

WORKDIR /src
COPY Cargo.* ./
COPY src/ ./src/
RUN cargo build --release

# ---

FROM debian:bullseye-slim

RUN apt-get update &&\
    apt-get install -y tini &&\
    rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/s5pp /usr/local/bin
ENV RUST_LOG=info
ENV BIND=0.0.0.0:5005

ENTRYPOINT ["tini", "--"]
CMD ["s5pp"]
