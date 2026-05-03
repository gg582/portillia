CC ?= gcc
CFLAGS = -Wall -Wextra -O3 -I./include -I./libs/cwist/include -I./libs/cwist/lib/cjson -I./libs/libttak/include -I./libs/secp256k1/include -pthread
LDFLAGS = -L./libs/cwist -L./libs/cwist/lib/cjson -L./libs/cwist/lib/libttak/lib -L./libs/libttak/lib -L./libs/secp256k1/.libs -lcwist -lttak -lssl -lcrypto -lcjson -lsqlite3 -lttak -lcurl -ldl -lpthread -lcrypto -lsecp256k1

# Add cwist internal libs to include path
CFLAGS += -I./libs/cwist/lib/libttak/include -I./libs/cwist/lib -I./libs/cwist/lib/sqlite3 -I./libs/cwist/lib/uriparser/include

SRC_TYPES = src/types/types.c
SRC_UTILS = src/utils/crypto.c src/utils/network.c src/utils/log.c src/utils/ttak_stubs.c
SRC_PORTAL = src/portal/server.c src/portal/proxy.c src/portal/sni_parser.c \
             src/portal/transport/quic_backhaul.c src/portal/keyless/tls.c \
             src/portal/acme/manager.c src/portal/acme/cloudflare/provider.c src/portal/acme/route53/provider.c src/portal/acme/gcloud/provider.c \
             src/portal/discovery/discovery.c src/portal/settings.c \
             libs/cwist/src/net/http/mux.c
SRC_SDK = src/sdk/expose.c
SRC_COMMON_API = src/portal/api_server.c
SRC_RELAY_API = src/portal/api_server_relay.c

ALL_SRCS = $(SRC_TYPES) $(SRC_UTILS) $(SRC_PORTAL) $(SRC_SDK) $(SRC_COMMON_API)
ALL_OBJS = $(ALL_SRCS:.c=.o)

BIN_RELAY = bin/relay-server
BIN_PORTAL = bin/portal-tunnel
BIN_DEMO = bin/demo-app

.PHONY: all help libs build build-frontend build-docs build-tunnel build-server build-demo clean

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

libs:
	$(MAKE) -C libs/cwist
	cd libs/secp256k1 && ./autogen.sh && ./configure --enable-module-recovery --disable-shared && make

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
	# $(MAKE) -C libs/cwist clean
