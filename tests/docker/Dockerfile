# ubuntu:focal (20.04) - Has GLIBC 2.31 which is required for Bitcoin Core 29.1
FROM ubuntu:focal as build

ENV VERSION 29.1
ENV ARCH x86_64-linux-gnu

ARG BITCOIND_RPC_NETWORK
ARG BITCOIND_RPC_PORT
ARG BITCOIND_RPC_USERNAME
ARG BITCOIND_RPC_PASSWORD

ENV BITCOIND_RPC_NETWORK=regtest
ENV BITCOIND_RPC_PORT=18443
ENV BITCOIND_RPC_USERNAME=foo
ENV BITCOIND_RPC_PASSWORD=rpcpassword

RUN apt update
RUN apt install -y wget
RUN apt install -y curl

RUN mkdir -p /app/data
WORKDIR /app

RUN wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/SHA256SUMS
RUN wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/bitcoin-${VERSION}-${ARCH}.tar.gz

RUN sha256sum --ignore-missing --check SHA256SUMS
RUN tar -xvf bitcoin-${VERSION}-${ARCH}.tar.gz

RUN cp /app/bitcoin-${VERSION}/bin/bitcoind /usr/local/bin/
RUN cp /app/bitcoin-${VERSION}/bin/bitcoin-cli /usr/local/bin/

COPY tests/docker/entrypoint.sh tests/docker/cleanup.sh /app/
RUN chmod +x /app/entrypoint.sh /app/cleanup.sh

EXPOSE 18443

ENTRYPOINT ["./entrypoint.sh"]
