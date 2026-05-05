#include <portillia/sdk/expose.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void print_usage() {
    printf("portal-tunnel <command> [args]\n");
    printf("Commands:\n");
    printf("  expose <target> --relays <url>\n");
    printf("  version\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "version") == 0) {
        printf("Portillia %s (C implementation)\n", PORTILLIA_RELEASE_VERSION);
    } else if (strcmp(argv[1], "expose") == 0) {
        if (argc < 3) {
            printf("Usage: portal-tunnel expose <target> [--relays <url>]\n");
            return 1;
        }
        const char *target = argv[2];
        const char *relay = "http://localhost:4017";
        
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--relays") == 0 && i + 1 < argc) {
                relay = argv[i+1];
            }
        }

        LOG_INFO("SDK: Starting portal tunnel; target: %s, relay: %s", target, relay);

        portillia_expose_config_t cfg = {0};
        cfg.target_addr = (char *)target;
        cfg.relay_urls = (char **)&relay;
        cfg.relay_urls_count = 1;
        cfg.tcp_enabled = true;

        portillia_exposure_t *exp = portillia_expose(&cfg);
        if (!exp) {
            LOG_ERROR("SDK: Failed to create exposure");
            return 1;
        }

        // Keep main alive
        while (!exp->done) {
            sleep(1);
        }

        portillia_exposure_close(exp);
    } else {
        print_usage();
        return 1;
    }

    return 0;
}
