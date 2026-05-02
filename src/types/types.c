/** @file types.c
 * @brief Implementation of Portillia types and lifecycle management.
 */
#include <portillia/types/types.h>
#include <cwist/core/mem/alloc.h>
#include <string.h>

/**
 * @brief Creates a new identity structure.
 * @return Allocated portillia_identity pointer or NULL on failure.
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
 * @param id The identity pointer to destroy.
 */
void portillia_identity_destroy(portillia_identity *id) {
    if (!id) return;
    cwist_sstring_destroy(id->name);
    cwist_sstring_destroy(id->address);
    cwist_sstring_destroy(id->public_key);
    cwist_sstring_destroy(id->private_key);
    cwist_free(id);
}
