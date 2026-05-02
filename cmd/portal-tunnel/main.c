#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Function print_usage
 * @return void result
 */
void print_usage() {
    printf("portal-tunnel <command> [args]\n");
    printf("Commands:\n");
    printf("  expose <target>\n");
    printf("  list\n");
    printf("  version\n");
}

/**
 * @brief Function main
 * @param argc Parameter description
 * @param argv Parameter description
 * @return int result
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "version") == 0) {
        printf("Portillia %s\n", PORTILLIA_RELEASE_VERSION);
    } else if (strcmp(argv[1], "expose") == 0) {
        if (argc < 3) {
            printf("Usage: portal-tunnel expose <target>\n");
            return 1;
        }
        LOG_INFO("starting portal tunnel; target: %s", argv[2]);
        // TODO: Implement SDK expose logic
    } else {
        print_usage();
        return 1;
    }

    return 0;
}
