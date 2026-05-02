CC ?= gcc
CFLAGS = -Wall -Wextra -O2 -I./include -I./libs/cwist/include -pthread
LDFLAGS = -L./libs/cwist -L./libs/cwist/lib/libttak/lib -L./libs/cwist/lib/cjson -lcwist -lssl -lcrypto -lcjson -lsqlite3 -lttak -ldl -lpthread

# Add cwist internal libs to include path
CFLAGS += -I./libs/cwist/lib/libttak/include -I./libs/cwist/lib -I./libs/cwist/lib/sqlite3 -I./libs/cwist/lib/uriparser/include

SRC_TYPES = src/types/types.c
SRC_UTILS = src/utils/crypto.c src/utils/network.c src/utils/log.c
SRC_PORTAL = src/portal/server.c src/portal/api_server.c src/portal/proxy.c src/portal/sni_parser.c \
             src/portal/transport/quic_backhaul.c src/portal/keyless/tls.c
SRC_SDK = src/sdk/expose.c

ALL_SRCS = $(SRC_TYPES) $(SRC_UTILS) $(SRC_PORTAL) $(SRC_SDK)
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

build: build-frontend build-tunnel build-server build-demo

build-frontend:
	cd frontend && npm install && npm run build
	mkdir -p cmd/relay-server/dist
	cp -r frontend/dist cmd/relay-server/dist/app

build-tunnel: libs cmd/portal-tunnel/main.o $(ALL_OBJS)
	@mkdir -p bin
	$(CC) -o $(BIN_PORTAL) cmd/portal-tunnel/main.o $(ALL_OBJS) $(LDFLAGS)

build-server: libs cmd/relay-server/main.o $(ALL_OBJS)
	@mkdir -p bin
	$(CC) -o $(BIN_RELAY) cmd/relay-server/main.o $(ALL_OBJS) $(LDFLAGS)

build-demo: libs cmd/demo-app/main.o $(ALL_OBJS)
	@mkdir -p bin
	$(CC) -o $(BIN_DEMO) cmd/demo-app/main.o $(ALL_OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf bin
	rm -f $(ALL_OBJS) cmd/relay-server/main.o cmd/portal-tunnel/main.o cmd/demo-app/main.o
	rm -rf cmd/relay-server/dist/app
	# $(MAKE) -C libs/cwist clean
