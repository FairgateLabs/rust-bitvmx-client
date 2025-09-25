FROM rust:latest

RUN apt-get update && \
    apt-get install -y wget build-essential git pkg-config libssl-dev clang netcat-openbsd

RUN mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts && \
    chmod 600 /root/.ssh/known_hosts

RUN mkdir -p /app/data

WORKDIR /app

RUN --mount=type=ssh git clone git@github.com:FairgateLabs/rust-bitvmx-workspace.git
RUN --mount=type=ssh cd rust-bitvmx-workspace && git submodule update --init --recursive --remote

WORKDIR /app/rust-bitvmx-workspace/rust-bitvmx-client

# Remove ./config to build without default configs, they should be mounted in docker-compose.yml at runtime
RUN rm -rf ./config
RUN mkdir ./config

COPY docker/run.sh ./
RUN chmod +x ./run.sh

RUN cargo build --release

ENTRYPOINT ["./run.sh"]