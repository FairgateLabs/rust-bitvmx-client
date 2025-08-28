# ubuntu:bionic
FROM ubuntu@sha256:8d31dad0c58f552e890d68bbfb735588b6b820a46e459672d96e585871acc110 as build

# Build inspired by bitcoin-core snap
# See https://github.com/bitcoin-core/packaging/blob/master/snap/snapcraft.yaml

ENV VERSION 24.0.1
ENV ARCH x86_64-linux-gnu

ARG BITCOIND_RPC_NETWORK
ARG BITCOIND_RPC_PORT
ARG BITCOIND_RPC_USERNAME
ARG BITCOIND_RPC_PASSWORD

# Hardcoded values instead of using ARGs
ENV BITCOIND_RPC_NETWORK=regtest
ENV BITCOIND_RPC_PORT=18443
ENV BITCOIND_RPC_USERNAME=foo
ENV BITCOIND_RPC_PASSWORD=rpcpassword

RUN apt update
RUN apt install -y wget
RUN apt install -y curl
RUN apt install -y librocksdb-dev 

RUN mkdir -p /app/data
WORKDIR /app

RUN wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/SHA256SUMS
RUN wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/bitcoin-${VERSION}-${ARCH}.tar.gz

RUN sha256sum --ignore-missing --check SHA256SUMS
RUN tar -xvf bitcoin-${VERSION}-${ARCH}.tar.gz

RUN cp /app/bitcoin-${VERSION}/bin/bitcoind /usr/local/bin/
RUN cp /app/bitcoin-${VERSION}/bin/bitcoin-cli /usr/local/bin/

COPY tests/entrypoint.sh tests/cleanup.sh /app/

EXPOSE 18443

ENTRYPOINT ["./entrypoint.sh"]