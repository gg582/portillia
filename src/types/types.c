/** @file types.c
 * @brief Implementation of Portillia types and lifecycle management.
 */
#include <portillia/types/types.h>
#include <cwist/core/mem/alloc.h>
#include <string.h>

/**
 * @brief Creates a new identity structure.
 */
portillia_identity *portillia_identity_create(void) {
    portillia_identity *id = cwist_alloc(sizeof(portillia_identity));
    if (!id) return NULL;
    id->name = cwist_sstring_create();
    id->address = cwist_sstring_create();
    id->public_key = cwist_sstring_create();
    id->private_key = cwist_sstring_create();
    return id;
}

/**
 * @brief Frees an identity structure.
 */
void portillia_identity_destroy(portillia_identity *id) {
    if (!id) return;
    cwist_sstring_destroy(id->name);
    cwist_sstring_destroy(id->address);
    cwist_sstring_destroy(id->public_key);
    cwist_sstring_destroy(id->private_key);
    cwist_free(id);
}

/**
 * @brief Creates a new lease structure.
 */
portillia_lease *portillia_lease_create(void) {
    portillia_lease *l = cwist_alloc(sizeof(portillia_lease));
    if (!l) return NULL;
    l->name = cwist_sstring_create();
    l->hostname = cwist_sstring_create();
    l->tcp_addr = cwist_sstring_create();
    l->hop_token = cwist_sstring_create();
    l->hop_next_overlay_ipv4 = cwist_sstring_create();
    l->hop_next_token = cwist_sstring_create();
    return l;
}

/**
 * @brief Frees a lease structure.
 */
void portillia_lease_destroy(portillia_lease *l) {
    if (!l) return;
    cwist_sstring_destroy(l->name);
    cwist_sstring_destroy(l->hostname);
    cwist_sstring_destroy(l->tcp_addr);
    cwist_sstring_destroy(l->hop_token);
    cwist_sstring_destroy(l->hop_next_overlay_ipv4);
    cwist_sstring_destroy(l->hop_next_token);
    cwist_free(l);
}