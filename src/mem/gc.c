/** @file gc.c
 * @brief Portillia EpochGC integration layer implementation.
 */

#include <portillia/mem/gc.h>
#include <ttak/mem/mem.h>
#include <ttak/timing/timing.h>
#include <stdio.h>
#include <stdlib.h>

static portillia_gc_t g_portillia_gc = {0};

portillia_gc_t *portillia_gc_global(void) {
    return &g_portillia_gc;
}

void portillia_gc_init_global(void) {
    portillia_gc_t *gc = &g_portillia_gc;
    if (atomic_exchange(&gc->initialized, true)) {
        return; /* already initialized */
    }
    pthread_mutex_init(&gc->lock, NULL);
    ttak_epoch_gc_init(&gc->epoch_gc);
    atomic_store(&gc->alloc_count, 0);
    atomic_store(&gc->free_count, 0);
}

void portillia_gc_destroy_global(void) {
    portillia_gc_t *gc = &g_portillia_gc;
    if (!atomic_load(&gc->initialized)) {
        return;
    }
    ttak_epoch_gc_destroy(&gc->epoch_gc);
    pthread_mutex_destroy(&gc->lock);
    atomic_store(&gc->initialized, false);
}

void *portillia_gc_alloc(size_t size) {
    if (size == 0) return NULL;
    portillia_gc_t *gc = portillia_gc_global();
    if (!atomic_load(&gc->initialized)) {
        portillia_gc_init_global();
    }

    void *ptr = malloc(size);
    if (!ptr) return NULL;

    ttak_epoch_gc_register(&gc->epoch_gc, ptr, size);
    atomic_fetch_add(&gc->alloc_count, 1);
    return ptr;
}

void *portillia_gc_calloc(size_t nmemb, size_t size) {
    if (nmemb == 0 || size == 0) return NULL;
    if (size != 0 && nmemb > SIZE_MAX / size) return NULL; /* overflow */

    size_t total = nmemb * size;
    void *ptr = portillia_gc_alloc(total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

char *portillia_gc_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *dup = (char *)portillia_gc_alloc(len);
    if (dup) memcpy(dup, s, len);
    return dup;
}

void *portillia_gc_memdup(const void *src, size_t size) {
    if (!src || size == 0) return NULL;
    void *dup = portillia_gc_alloc(size);
    if (dup) memcpy(dup, src, size);
    return dup;
}

void *portillia_gc_realloc(void *ptr, size_t new_size) {
    if (!ptr) return portillia_gc_alloc(new_size);
    if (new_size == 0) {
        portillia_gc_free(ptr);
        return NULL;
    }

    portillia_gc_t *gc = portillia_gc_global();
    /* Try to find and remove the old node from the tree so we don't leak bookkeeping. */
    ttak_mem_node_t *node = ttak_mem_tree_find_node(&gc->epoch_gc.tree, ptr);
    if (node) {
        ttak_mem_tree_remove(&gc->epoch_gc.tree, node);
    }

    void *new_ptr = realloc(ptr, new_size);
    if (new_ptr) {
        ttak_epoch_gc_register(&gc->epoch_gc, new_ptr, new_size);
    } else if (new_size > 0) {
        /* realloc failed; old ptr is still valid. Re-register it. */
        ttak_epoch_gc_register(&gc->epoch_gc, ptr, new_size);
    }
    return new_ptr;
}

void portillia_gc_free_later(void *ptr) {
    if (!ptr) return;
    portillia_gc_t *gc = portillia_gc_global();
    if (!atomic_load(&gc->initialized)) return;

    atomic_fetch_add(&gc->free_count, 1);
    ttak_epoch_retire(ptr, free);
}

void portillia_gc_free(void *ptr) {
    if (!ptr) return;
    portillia_gc_t *gc = portillia_gc_global();
    if (atomic_load(&gc->initialized)) {
        ttak_mem_node_t *node = ttak_mem_tree_find_node(&gc->epoch_gc.tree, ptr);
        if (node) {
            ttak_mem_tree_remove(&gc->epoch_gc.tree, node);
        }
    }
    free(ptr);
}

void portillia_gc_rotate(void) {
    portillia_gc_t *gc = portillia_gc_global();
    if (!atomic_load(&gc->initialized)) return;
    ttak_epoch_gc_rotate(&gc->epoch_gc);
}

void portillia_gc_reclaim(void) {
    portillia_gc_t *gc = portillia_gc_global();
    if (!atomic_load(&gc->initialized)) return;
    ttak_epoch_reclaim();
}
