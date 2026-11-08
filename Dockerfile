FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p tidemark-cli

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/tidemark /usr/local/bin/tidemark
COPY deploy/watcher.sh /usr/local/bin/tidemark-watcher
ENV TIDEMARK_DATA=/data
ENTRYPOINT ["tini", "--", "tidemark-watcher"]
