CC ?= gcc
CFLAGS = -Wall -Wextra -O3 -I./include -I./libs/cwist/include -I./libs/cwist/lib/cjson -I./libs/libttak/include -I./libs/secp256k1/include -pthread
LDFLAGS = -L./libs/cwist -L./libs/cwist/lib/cjson -L./libs/cwist/lib/libttak/lib -L./libs/libttak/lib -L./libs/secp256k1/.libs -lcwist -lttak -lssl -lcrypto -lcjson -lsqlite3 -lttak -lcurl -ldl -lpthread -lcrypto -lsecp256k1 -lm

# ngtcp2 detection (supports both distro packages and source builds)
NGTCP2_CFLAGS := $(shell pkg-config --cflags libngtcp2 2>/dev/null)
NGTCP2_LDFLAGS := $(shell pkg-config --libs-only-L libngtcp2 2>/dev/null)
NGTCP2_LIBS := $(shell pkg-config --libs-only-l libngtcp2 2>/dev/null)
NGTCP2_CRYPTO_LIBS := $(shell pkg-config --libs-only-l libngtcp2_crypto_quictls 2>/dev/null || pkg-config --libs-only-l libngtcp2_crypto_ossl 2>/dev/null)

# Fallback if pkg-config doesn't find ngtcp2
ifeq ($(NGTCP2_LIBS),)
    NGTCP2_CFLAGS := -I/usr/local/include
    NGTCP2_LDFLAGS := -L/usr/local/lib
    NGTCP2_LIBS := -lngtcp2
    NGTCP2_CRYPTO_LIBS := $(shell test -f /usr/local/lib/libngtcp2_crypto_quictls.a && echo -lngtcp2_crypto_quictls || echo -lngtcp2_crypto_ossl)
endif

CFLAGS += $(NGTCP2_CFLAGS)
LDFLAGS += $(NGTCP2_LDFLAGS) $(NGTCP2_LIBS) $(NGTCP2_CRYPTO_LIBS)

# Add cwist internal libs to include path
CFLAGS += -I./libs/cwist/lib/libttak/include -I./libs/cwist/lib -I./libs/cwist/lib/sqlite3 -I./libs/cwist/lib/uriparser/include

SRC_MEM = src/mem/gc.c
SRC_TYPES = src/types/types.c
SRC_UTILS = src/utils/crypto.c src/utils/network.c src/utils/log.c src/utils/ttak_stubs.c
SRC_DISCOVERY = src/discovery/relay_set.c
SRC_TRANSPORT = src/transport/stream_client.c src/transport/datagram_client.c src/transport/quic_conn.c
SRC_PORTAL = src/portal/server.c src/portal/proxy.c src/portal/sni_parser.c \
             src/portal/transport/quic_backhaul.c src/portal/keyless/tls.c src/portal/keyless/ech.c \
             src/portal/acme/manager.c src/portal/acme/cloudflare/provider.c src/portal/acme/route53/provider.c src/portal/acme/gcloud/provider.c \
             src/portal/discovery/discovery.c src/portal/settings.c \
             libs/cwist/src/net/http/mux.c
SRC_SDK = src/sdk/expose.c src/sdk/listener.c src/sdk/api_client.c src/sdk/http_runtime.c
SRC_COMMON_API = src/portal/api_server.c
SRC_RELAY_API = src/portal/api_server_relay.c

ALL_SRCS = $(SRC_MEM) $(SRC_TYPES) $(SRC_UTILS) $(SRC_DISCOVERY) $(SRC_TRANSPORT) $(SRC_PORTAL) $(SRC_SDK) $(SRC_COMMON_API)
ALL_OBJS = $(ALL_SRCS:.c=.o)

BIN_RELAY = bin/relay-server
BIN_PORTAL = bin/portal-tunnel
BIN_DEMO = bin/demo-app

.PHONY: all help build build-frontend build-docs build-tunnel build-server build-demo clean cwist-libs

all: build

help:
	@echo "Available targets:"
	@echo "  make build             - Build everything (frontend, tunnel, server, demo)"
	@echo "  make build-frontend    - Build React frontend"
	@echo "  make build-docs        - Build documentation site"
	@echo "  make build-tunnel      - Build portal-tunnel binaries (C implementation)"
	@echo "  make build-server      - Build relay server (C implementation)"
	@echo "  make build-demo        - Build demo app (C implementation)"
	@echo "  make clean             - Remove build artifacts"

cwist-libs:
	$(MAKE) -C libs/cwist

libs/secp256k1/.libs/libsecp256k1.a:
	cd libs/secp256k1 && ./autogen.sh && ./configure --enable-module-recovery --disable-shared && make

libs: cwist-libs libs/secp256k1/.libs/libsecp256k1.a

build: build-frontend build-tunnel build-server build-demo

build-frontend:
	cd frontend && npm install && npm run build

build-tunnel: libs cmd/portal-tunnel/main.o $(ALL_OBJS)
	@mkdir -p bin
	$(CC) -o $(BIN_PORTAL) cmd/portal-tunnel/main.o $(ALL_OBJS) $(LDFLAGS)

build-server: libs cmd/relay-server/main.o $(ALL_OBJS) src/portal/api_server_relay.o
	@mkdir -p bin
	$(CC) -o $(BIN_RELAY) cmd/relay-server/main.o $(ALL_OBJS) src/portal/api_server_relay.o $(LDFLAGS)

build-demo: libs cmd/demo-app/main.o $(ALL_OBJS)
	@mkdir -p bin
	$(CC) -o $(BIN_DEMO) cmd/demo-app/main.o $(ALL_OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

src/portal/api_server_relay.o: src/portal/api_server_relay.c
	$(CC) $(CFLAGS) -DPORTILLIA_RELAY_SERVER_BUILD -c $< -o $@

clean:
	rm -rf bin
	rm -f $(ALL_OBJS) cmd/relay-server/main.o cmd/portal-tunnel/main.o cmd/demo-app/main.o
	rm -rf cmd/relay-server/dist/app
	$(MAKE) -C libs/cwist clean
	cd libs/secp256k1 && make clean || true
