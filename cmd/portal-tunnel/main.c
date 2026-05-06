#include <portillia/sdk/expose.h>
#include <portillia/types/types.h>
#include <portillia/portal/agent/control.h>
#include <portillia/utils/log.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void print_usage() {
    printf("portal-tunnel <command> [args]\n");
    printf("Commands:\n");
    printf("  expose <target> [--relays <url>] [--insecure-skip-verify]\n");
    printf("  agent start [--control-addr <addr>]\n");
    printf("  agent status [--control-addr <addr>]\n");
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
            printf("Usage: portal-tunnel expose <target> [--relays <url>] [--insecure-skip-verify]\n");
            return 1;
        }
        const char *target = argv[2];
        const char *relay = "http://localhost:4017";
        bool insecure_skip_verify = false;
        
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--relays") == 0 && i + 1 < argc) {
                relay = argv[i+1];
                i++;
                continue;
            }
            if (strcmp(argv[i], "--insecure-skip-verify") == 0) {
                insecure_skip_verify = true;
            }
        }

        LOG_INFO("SDK: Starting portal tunnel; target: %s, relay: %s", target, relay);
        if (insecure_skip_verify) {
            LOG_WARN("SDK: TLS certificate verification disabled for relay API requests");
        }

        portillia_expose_config_t cfg = {0};
        cfg.target_addr = (char *)target;
        cfg.relay_urls = (char **)&relay;
        cfg.relay_urls_count = 1;
        cfg.tcp_enabled = true;
        cfg.insecure_skip_verify = insecure_skip_verify;

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
    } else if (strcmp(argv[1], "agent") == 0) {
        if (argc < 3) {
            printf("Usage: portal-tunnel agent <subcommand> [args]\n");
            printf("Subcommands:\n");
            printf("  start [--control-addr <addr>]\n");
            printf("  status [--control-addr <addr>]\n");
            return 1;
        }
        const char *control_addr = "127.0.0.1:4019";
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--control-addr") == 0 && i + 1 < argc) {
                control_addr = argv[i+1];
                i++;
            }
        }
        if (strcmp(argv[2], "start") == 0) {
            return portillia_agent_control_server_run(control_addr);
        } else if (strcmp(argv[2], "status") == 0) {
            char url[2048];
            snprintf(url, sizeof(url), "http://%s/v1/agent/status", control_addr);
            char cmd[4096];
            snprintf(cmd, sizeof(cmd), "curl -fsSL %s", url);
            int rc = system(cmd);
            printf("\n");
            return rc;
        } else {
            printf("Unknown agent subcommand: %s\n", argv[2]);
            return 1;
        }
    } else {
        print_usage();
        return 1;
    }

    return 0;
}
