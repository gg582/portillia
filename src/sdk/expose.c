/**
 * @file expose.c
 * @brief Implementation of the Portal SDK service exposure logic.
 *
 * This module handles the registration of local services with a relay server,
 * maintains a pool of reverse tunnel sessions, and bridges traffic between
 * the relay and the local target.
 */

#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <portillia/utils/crypto.h>
#include <cwist/core/sstring/sstring.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

/**
 * @struct portillia_exposure
 * @brief Context for a running service exposure.
 */
typedef struct portillia_exposure {
    portillia_identity *identity; /**< Cryptographic identity of the tunnel */
    char *target_addr;           /**< Local address (e.g., localhost:80) */
    char *relay_url;             /**< Relay server API URL */
    char *access_token;          /**< Session token from registration */
    char *hostname;              /**< Assigned public hostname */
    bool running;                /**< Lifecycle control flag */
} portillia_exposure;

/**
 * @brief Internal callback for libcurl to handle string responses.
 */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char **res = (char **)userp;
    *res = realloc(*res, realsize + 1);
    if (*res) {
        memcpy(*res, contents, realsize);
        (*res)[realsize] = 0;
    }
    return realsize;
}

/**
 * @brief Data pump thread function to bridge relay and target.
 * @param arg Pointer to two file descriptors [relay_fd, target_fd].
 */
void *data_pump_thread(void *arg) {
    int *fds = (int *)arg;
    int relay_fd = fds[0];
    int target_fd = fds[1];
    free(fds);

    extern void portillia_proxy_bridge(int fd1, int fd2);
    portillia_proxy_bridge(relay_fd, target_fd);
    return NULL;
}

/**
 * @brief Reverse session worker loop.
 * Connects to /sdk/connect and waits for traffic from the relay.
 */
void *reverse_session_thread(void *arg) {
    portillia_exposure *e = (portillia_exposure *)arg;
    
    while (e->running) {
        char host[256];
        int port = 4017;
        // Parse relay URL (Simplified)
        if (sscanf(e->relay_url, "http://%[^:]:%d", host, &port) < 1) {
            sscanf(e->relay_url, "https://%[^:]:%d", host, &port);
        }

        struct hostent *server = gethostbyname(host);
        if (!server) { sleep(5); continue; }

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(port) };
        memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            close(sockfd);
            sleep(5);
            continue;
        }

        char req[1024];
        snprintf(req, sizeof(req), 
            "GET /sdk/connect HTTP/1.1\r\n"
            "Host: %s\r\n"
            "X-Portal-Access-Token: %s\r\n"
            "X-Portal-Hostname: %s\r\n"
            "Connection: keep-alive\r\n\r\n", 
            host, e->access_token, e->hostname);
        
        write(sockfd, req, strlen(req));

        char resp_buf[1024];
        ssize_t nr = read(sockfd, resp_buf, sizeof(resp_buf) - 1);
        if (nr > 0) {
            resp_buf[nr] = '\0';
            if (strstr(resp_buf, "200 OK")) {
                uint8_t marker;
                if (read(sockfd, &marker, 1) == 1 && marker == 0x02) {
                    char target_host[256] = "localhost";
                    int target_port = 80;
                    sscanf(e->target_addr, "%[^:]:%d", target_host, &target_port);

                    int target_fd = socket(AF_INET, SOCK_STREAM, 0);
                    struct hostent *t_server = gethostbyname(target_host);
                    if (t_server) {
                        struct sockaddr_in t_addr = { .sin_family = AF_INET, .sin_port = htons(target_port) };
                        memcpy(&t_addr.sin_addr.s_addr, t_server->h_addr, t_server->h_length);

                        if (connect(target_fd, (struct sockaddr *)&t_addr, sizeof(t_addr)) == 0) {
                            int *fds = malloc(sizeof(int) * 2);
                            fds[0] = sockfd; fds[1] = target_fd;
                            pthread_t tid;
                            pthread_create(&tid, NULL, data_pump_thread, fds);
                            pthread_detach(tid);
                            continue; 
                        }
                    }
                    close(target_fd);
                }
            }
        }
        close(sockfd);
        if (e->running) sleep(2); 
    }
    return NULL;
}

/**
 * @brief Exposes a local service via Portillia relay.
 * @param target Local address to expose.
 * @param relay_url Relay server URL.
 * @return Exposure context on success, NULL on failure.
 */
portillia_exposure *portillia_expose(const char *target, const char *relay_url) {
    portillia_exposure *e = calloc(1, sizeof(portillia_exposure));
    if (!e) return NULL;
    
    e->target_addr = strdup(target);
    e->relay_url = strdup(relay_url);
    e->running = true;
    e->identity = portillia_identity_create();

    char priv_hex[65] = {0};
    char addr[43] = {0};
    if (portillia_crypto_generate_identity(priv_hex, addr) == 0) {
        cwist_sstring_assign(e->identity->address, addr);
        cwist_sstring_assign(e->identity->private_key, priv_hex);
    } else {
        LOG_ERROR("SDK: Failed to generate identity");
        free(e->target_addr); free(e->relay_url); portillia_identity_destroy(e->identity); free(e);
        return NULL;
    }

    // Registration
    CURL *curl = curl_easy_init();
    if (curl) {
        char reg_url[1024];
        snprintf(reg_url, sizeof(reg_url), "%s/sdk/register", relay_url);
        
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "name", "c-sdk-tunnel");
        cJSON_AddStringToObject(root, "identity", e->identity->address->data);
        char *json = cJSON_PrintUnformatted(root);

        char *response = malloc(1);
        response[0] = '\0';
        curl_easy_setopt(curl, CURLOPT_URL, reg_url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        
        if (curl_easy_perform(curl) == CURLE_OK) {
            cJSON *res = cJSON_Parse(response);
            if (res) {
                cJSON *data = cJSON_GetObjectItem(res, "data");
                if (data) {
                    cJSON *tok = cJSON_GetObjectItem(data, "access_token");
                    cJSON *host = cJSON_GetObjectItem(data, "hostname");
                    if (tok && host) {
                        e->access_token = strdup(tok->valuestring);
                        e->hostname = strdup(host->valuestring);
                        LOG_INFO("SDK: Registered tunnel for %s", e->hostname);
                    }
                }
                cJSON_Delete(res);
            }
        }
        free(json);
        free(response);
        cJSON_Delete(root);
        curl_easy_cleanup(curl);
    }

    if (e->access_token) {
        for (int i = 0; i < 4; i++) {
            pthread_t tid;
            pthread_create(&tid, NULL, reverse_session_thread, e);
            pthread_detach(tid);
        }
    } else {
        LOG_ERROR("SDK: Failed to register with relay %s", relay_url);
        free(e->target_addr); free(e->relay_url); free(e);
        return NULL;
    }

    return e;
}

/**
 * @brief Stops a running service exposure.
 * @param e Exposure context to stop.
 */
void portillia_exposure_stop(portillia_exposure *e) {
    if (!e) return;
    e->running = false;
    free(e->target_addr);
    free(e->relay_url);
    if (e->access_token) free(e->access_token);
    if (e->hostname) free(e->hostname);
    free(e);
}