#include <portillia/portal/discovery/discovery.h>
#include <ttak/ttak.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cJSON.h>
#include <portillia/utils/log.h>
#include <unistd.h>

static CURLM *multi_handle = NULL;

static void check_multi_info(void) {
    int still_running;
    CURLMsg *msg;
    int msgs_left;
    while ((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
        if (msg->msg == CURLMSG_DONE) {
            curl_multi_remove_handle(multi_handle, msg->easy_handle);
            curl_easy_cleanup(msg->easy_handle);
        }
    }
}

static void discovery_task(ttak_task_t *task, void *arg) {
    discovery_config *cfg = (discovery_config *)arg;
    
    portillia_relay_descriptor desc;
    desc.api_https_addr = cwist_sstring_create_from_str(cfg->relay_url);
    desc.version = cwist_sstring_create_from_str("v2.1.8-c");
    desc.active_connections = 0; // Telemetry placeholder
    desc.tcp_bps = 0.0;          // Telemetry placeholder

    // Mock Signing Logic
    desc.signature = cwist_sstring_create_from_str("mock_signature"); 
    
    // Announce
    portillia_discovery_announce(cfg, &desc);
    
    cwist_sstring_destroy(desc.api_https_addr);
    cwist_sstring_destroy(desc.version);
    cwist_sstring_destroy(desc.signature);

    ttak_sleep(30000);
    ttak_schedule(discovery_task, arg);
}

void *discovery_maintenance_loop(void *arg) {
    ttak_init();
    multi_handle = curl_multi_init();
    ttak_schedule(discovery_task, arg);
    ttak_run();
    curl_multi_cleanup(multi_handle);
    return NULL;
}

