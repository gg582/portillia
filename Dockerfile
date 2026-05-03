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
    git \
    libssl-dev \
    libsqlite3-dev \
    libcurl4-openssl-dev \
    pkg-config \
    ca-certificates \
    doxygen \
    graphviz \
    autoconf \
    automake \
    libtool \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Robustly handle missing cwist submodule (e.g. when built without local submodules initialized)
RUN if [ ! -f libs/cwist/Makefile ]; then \
        echo "cwist submodule missing, cloning..." && \
        rm -rf libs/cwist && \
        git clone --recursive https://github.com/religiya-serdtsa/cwist libs/cwist; \
    fi

# Robustly handle missing secp256k1 submodule
RUN if [ ! -f libs/secp256k1/autogen.sh ]; then \
        echo "secp256k1 submodule missing, cloning..." && \
        rm -rf libs/secp256k1 && \
        git clone https://github.com/bitcoin-core/secp256k1.git libs/secp256k1; \
    fi

# Ensure stubs are available for cwist
RUN cp include/ttak_stubs.h libs/cwist/include/

# Build secp256k1
RUN cd libs/secp256k1 && ./autogen.sh && ./configure --enable-module-recovery --disable-shared && make clean && make

# Build cwist and portillia
RUN make libs
RUN make build-tunnel build-server build-demo

# Stage 3: Final image
FROM goacme/lego:latest AS lego-bin
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libsqlite3-0 \
    libcurl4 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=lego-bin /lego /usr/bin/lego
COPY --from=c-builder /src/bin/relay-server /usr/bin/relay-server
COPY --from=c-builder /src/bin/portal-tunnel /usr/bin/portal-tunnel
COPY --from=frontend-builder /src/cmd/relay-server/dist/app /app/dist

ENV STATIC_DIR=/app/dist
ENV TZ=UTC
EXPOSE 8080
ENTRYPOINT ["/usr/bin/relay-server"]
