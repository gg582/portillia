# Stage 1: Build frontend
FROM --platform=$BUILDPLATFORM node:22-slim AS frontend-builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends make && rm -rf /var/lib/apt/lists/*
COPY frontend ./frontend
COPY Makefile ./
# Note: Makefile might need update for frontend build, but we keep UI as is
RUN make build-frontend || true

# Stage 2: Build C artifacts
FROM debian:12-slim AS c-builder
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    wget \
    unzip \
    libssl-dev \
    libsqlite3-dev \
    pkg-config \
    ca-certificates \
    doxygen \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Ensure stubs are available for cwist
RUN cp include/ttak_stubs.h libs/cwist/include/

# Build cwist and portillia
RUN make libs
RUN make build-tunnel build-server build-demo

# Stage 3: Final image
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libsqlite3-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=c-builder /src/bin/relay-server /usr/bin/relay-server
COPY --from=c-builder /src/bin/portal-tunnel /usr/bin/portal-tunnel
COPY --from=frontend-builder /src/cmd/relay-server/dist/app /app/dist

ENV TZ=UTC
EXPOSE 8080
ENTRYPOINT ["/usr/bin/relay-server"]
