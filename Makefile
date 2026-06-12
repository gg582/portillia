CC ?= gcc
CFLAGS = -Wall -Wextra -O3 -I. -I./include -I./libs/cwist/include -I./libs/cwist/lib/cjson -I./libs/libttak/include -I./libs/secp256k1/include -I./libs/keccak -pthread
LDFLAGS = -L. -L./libs/cwist -L./libs/cwist/lib/cjson -L./libs/cwist/lib/libttak/lib -L./libs/libttak/lib -L./libs/secp256k1/.libs -lcwist -lttak -lssl -lcrypto -lcjson -lsqlite3 -lttak -lcurl -ldl -lpthread -lcrypto -lsecp256k1 -lm -lportal_bridge

# ngtcp2 detection (supports both distro packages and source builds)
NGTCP2_CFLAGS := $(shell pkg-config --cflags libngtcp2 2>/dev/null)
NGTCP2_LDFLAGS := $(shell pkg-config --libs-only-L libngtcp2 2>/dev/null)
NGTCP2_LIBS := $(shell pkg-config --libs-only-l libngtcp2 2>/dev/null)
NGTCP2_CRYPTO_LIBS := $(shell pkg-config --libs-only-l libngtcp2_crypto_quictls 2>/dev/null || pkg-config --libs-only-l libngtcp2_crypto_ossl 2>/dev/null)

# If ngtcp2 is not available, leave flags empty
ifeq ($(NGTCP2_LIBS),)
    NGTCP2_CFLAGS :=
    NGTCP2_LDFLAGS :=
    NGTCP2_LIBS :=
    NGTCP2_CRYPTO_LIBS :=
endif

CFLAGS += $(NGTCP2_CFLAGS)
LDFLAGS += $(NGTCP2_LDFLAGS) $(NGTCP2_LIBS) $(NGTCP2_CRYPTO_LIBS) -L./rust_bridge/target/release -lportillia_bridge_rust

# Add cwist internal libs to include path
CFLAGS += -I./libs/cwist/lib/libttak/include -I./libs/cwist/lib -I./libs/cwist/lib/sqlite3 -I./libs/cwist/lib/uriparser/include

SRC_MEM = src/mem/gc.c
SRC_TYPES = src/types/types.c
SRC_UTILS = src/utils/crypto.c src/utils/network.c src/utils/log.c src/utils/ttak_stubs.c
NGTCP2_HEADER := $(shell test -f /usr/include/ngtcp2/ngtcp2.h || test -f /usr/local/include/ngtcp2/ngtcp2.h && echo yes || echo no)

# quic_conn.c contains its own HAS_NGTCP2 guards, so always compile it
SRC_TRANSPORT = src/transport/stream_client.c src/transport/datagram_client.c src/transport/quic_conn.c

SRC_DISCOVERY = src/portal/discovery/relay_set.c src/portal/discovery/mols.c
SRC_PORTAL = src/portal/server.c src/portal/proxy.c src/portal/sni_parser.c \
             src/portal/transport/quic_backhaul.c src/portal/keyless/tls.c src/portal/keyless/ech.c \
             src/portal/acme/manager.c src/portal/acme/cloudflare/provider.c src/portal/acme/route53/provider.c src/portal/acme/gcloud/provider.c \
             src/portal/discovery/discovery.c src/portal/policy/policy.c src/portal/settings.c src/portal/agent/control.c \
             libs/cwist/src/net/http/mux.c
SRC_SDK = src/sdk/expose.c src/sdk/listener.c src/sdk/api_client.c src/sdk/http_runtime.c 
SRC_COMMON_API = src/portal/api_server.c
SRC_RELAY_API = src/portal/api_server_relay.c

ALL_SRCS = $(SRC_MEM) $(SRC_TYPES) $(SRC_UTILS) $(SRC_DISCOVERY) $(SRC_TRANSPORT) $(SRC_PORTAL) $(SRC_SDK) $(SRC_COMMON_API) libs/keccak/sha3.c
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

libportal_bridge.so portal_bridge.h: go/bridge.go go/go.mod
	cd go && GOTOOLCHAIN=auto go mod tidy && GOTOOLCHAIN=auto go build -buildmode=c-shared -o libportal_bridge.so bridge.go
	cp go/libportal_bridge.so libportal_bridge.so
	cp go/libportal_bridge.h portal_bridge.h

rust_bridge/target/release/libportillia_bridge_rust.a:
	cd rust_bridge && cargo build --release

libs: cwist-libs libs/secp256k1/.libs/libsecp256k1.a rust_bridge/target/release/libportillia_bridge_rust.a

build: build-frontend build-tunnel build-server build-demo

build-frontend:
	cd frontend && npm install && npm run build

build-tunnel: libs libportal_bridge.so rust_bridge/target/release/libportillia_bridge_rust.a cmd/portal-tunnel/main.o $(ALL_OBJS)
	@mkdir -p bin
	$(CC) -o $(BIN_PORTAL) cmd/portal-tunnel/main.o $(ALL_OBJS) $(LDFLAGS) -Wl,-rpath,'$$ORIGIN'
	cp libportal_bridge.so bin/

build-server: libs libportal_bridge.so rust_bridge/target/release/libportillia_bridge_rust.a cmd/relay-server/main.o $(ALL_OBJS) src/portal/api_server_relay.o
	@mkdir -p bin
	$(CC) -o $(BIN_RELAY) cmd/relay-server/main.o $(ALL_OBJS) src/portal/api_server_relay.o $(LDFLAGS) -Wl,-rpath,'$$ORIGIN'
	cp libportal_bridge.so bin/

build-demo: libs libportal_bridge.so rust_bridge/target/release/libportillia_bridge_rust.a cmd/demo-app/main.o $(ALL_OBJS)
	@mkdir -p bin
	$(CC) -o $(BIN_DEMO) cmd/demo-app/main.o $(ALL_OBJS) $(LDFLAGS) -Wl,-rpath,'$$ORIGIN'
	cp libportal_bridge.so bin/

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

src/portal/api_server_relay.o: src/portal/api_server_relay.c
	$(CC) $(CFLAGS) -DPORTILLIA_RELAY_SERVER_BUILD -c $< -o $@

src/portal/api_server.o: portal_bridge.h

clean:
	rm -rf bin
	rm -f $(ALL_OBJS) cmd/relay-server/main.o cmd/portal-tunnel/main.o cmd/demo-app/main.o
	rm -rf cmd/relay-server/dist/app
	$(MAKE) -C libs/cwist clean
	cd libs/secp256k1 && make clean || true
	cd rust_bridge && cargo clean || true
