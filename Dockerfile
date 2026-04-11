FROM rust:1.85-bookworm

WORKDIR /app

# Clone the nxp-se050 driver as a test dependency
RUN git clone https://github.com/imrank03/nxp-se050.git /app/nxp-se050

# Copy and apply driver patches
COPY patches/apply.sh /app/patches/apply.sh
RUN chmod +x /app/patches/apply.sh && /app/patches/apply.sh /app/nxp-se050

# Copy simulator source
COPY se050-sim/ /app/se050-sim/

# Build the simulator
RUN cd /app/se050-sim && cargo build 2>&1

# Run all tests (unit + integration) by default
CMD ["cargo", "test", "--manifest-path", "/app/se050-sim/Cargo.toml", "--", "--nocapture", "--test-threads=1"]
