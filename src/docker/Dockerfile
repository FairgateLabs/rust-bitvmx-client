FROM rust:latest

ARG BITCOIND_RPC_NETWORK
ARG BITCOIND_RPC_PORT
ARG BITCOIND_RPC_USERNAME
ARG BITCOIND_RPC_PASSWORD

ENV BITCOIND_RPC_NETWORK=${BITCOIND_RPC_NETWORK}
ENV BITCOIND_RPC_PORT=${BITCOIND_RPC_PORT}
ENV BITCOIND_RPC_USERNAME=${BITCOIND_RPC_USERNAME}
ENV BITCOIND_RPC_PASSWORD=${BITCOIND_RPC_PASSWORD}
ENV DOCKER_BUILDKIT=1

RUN apt update
RUN apt install -y wget
RUN apt-get install -y build-essential git

# Setup SSH known hosts
RUN mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts && \
    chmod 600 /root/.ssh/known_hosts

RUN mkdir -p /app/data
WORKDIR /app

RUN git clone --branch bitvmx https://github.com/FairgateLabs/rust-bitcoin-script/

RUN git clone --branch bitvmx https://github.com/FairgateLabs/rust-bitcoin-scriptexec/

RUN --mount=type=ssh git clone git@github.com:FairgateLabs/rust-bitvmx-key-manager.git

RUN --mount=type=ssh git clone git@github.com:FairgateLabs/rust-bitvmx-protocol-builder.git

RUN --mount=type=ssh git clone git@github.com:FairgateLabs/rust-bitvmx-orchestrator.git

RUN --mount=type=ssh git clone git@github.com:FairgateLabs/rust-p2p-handler.git

RUN --mount=type=ssh git clone git@github.com:FairgateLabs/rust-bitvmx-storage-backend.git

RUN --mount=type=ssh git clone git@github.com:FairgateLabs/rust-bitvmx-transaction-dispatcher.git

RUN --mount=type=ssh git clone git@github.com:FairgateLabs/rust-bitvmx-transaction-monitor.git

RUN --mount=type=ssh git clone git@github.com:FairgateLabs/rust-p2p-protocol.git

RUN --mount=type=ssh git clone git@github.com:FairgateLabs/rust-bitcoin-indexer.git

COPY ./ ./app

COPY ./Cargo.toml ./Cargo.lock ./app/

COPY src/docker/regtest.conf src/docker/entrypoint.sh src/docker/prover.sh src/docker/verifier.sh src/docker/cleanup.sh /app/

RUN chmod 400 ./*.conf
RUN chmod +x /app/prover.sh /app/verifier.sh

#RUN cd app && cargo build

EXPOSE ${BITCOIND_RPC_PORT}

ENTRYPOINT ["./entrypoint.sh"]