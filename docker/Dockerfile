# ----------- Build Stage -----------
FROM rust:1.90.0-bullseye AS builder

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget build-essential git pkg-config libssl-dev clang netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# SSH setup for private repos
RUN mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts && \
    chmod 600 /root/.ssh/known_hosts

WORKDIR /app

# Clone repo and submodules
# RUN --mount=type=ssh git clone --branch v0.1.2-alpha git@github.com:FairgateLabs/rust-bitvmx-workspace.git
# RUN --mount=type=ssh cd rust-bitvmx-workspace && git submodule update --init --recursive

# Workspace should be cloned before running the build in the tag/branch you want
COPY . /app/rust-bitvmx-workspace

WORKDIR /app/rust-bitvmx-workspace/rust-bitvmx-client

# Remove configs (mounted later at runtime)
RUN rm -rf ./config && mkdir ./config

# Copy run script
COPY rust-bitvmx-client/docker/run.sh ./
RUN chmod +x ./run.sh

# Build release binary
RUN cargo build --release

# ----------- Runtime Stage -----------
FROM debian:bullseye-slim AS runtime

# Install only minimal runtime dependencies
RUN apt-get update && \
    apt-get install -y libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled binary and run script from builder stage
COPY --from=builder /app/rust-bitvmx-workspace/rust-bitvmx-client/target/release/bitvmx-client /app/
COPY --from=builder /app/rust-bitvmx-workspace/rust-bitvmx-client/run.sh /app/

# Ensure run.sh is executable
RUN chmod +x /app/run.sh

ENTRYPOINT ["./run.sh"]
