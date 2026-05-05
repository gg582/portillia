/** @file gc.h
 * @brief Portillia EpochGC integration layer.
 *
 * Wraps libttak's ttak_epoch_gc_t and EBR primitives to provide a
 * unified, leak-safe memory management API for the C port of portal-tunnel.
 *
 * Rules:
 *  1. All heap allocations in portillia must go through portillia_gc_alloc/calloc/strdup.
 *  2. Objects that may outlive their creator or be accessed concurrently must be
 *     freed with portillia_gc_free_later() (EBR-based deferred reclamation).
 *  3. portillia_gc_rotate() is called periodically by a background thread.
 *  4. Critical sections that read shared data must bracket with
 *     portillia_gc_read_enter() / portillia_gc_read_exit().
 */
#ifndef PORTILLIA_MEM_GC_H
#define PORTILLIA_MEM_GC_H

#include <ttak/mem/epoch_gc.h>
#include <ttak/mem/epoch.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct portillia_gc {
    ttak_epoch_gc_t epoch_gc;
    pthread_mutex_t lock;
    _Atomic _Bool initialized;
    _Atomic uint64_t alloc_count;
    _Atomic uint64_t free_count;
} portillia_gc_t;

/* ---------- Global singleton ---------- */

portillia_gc_t *portillia_gc_global(void);
void portillia_gc_init_global(void);
void portillia_gc_destroy_global(void);

/* ---------- Allocation ---------- */

/**
 * @brief Allocate memory tracked by the global EpochGC.
 *
 * The returned pointer is registered with the current epoch.
 * Use portillia_gc_free_later() or portillia_gc_free() to release.
 */
void *portillia_gc_alloc(size_t size);

/**
 * @brief Zero-initialized allocation tracked by the global EpochGC.
 */
void *portillia_gc_calloc(size_t nmemb, size_t size);

/**
 * @brief Duplicate a C string using GC-tracked memory.
 */
char *portillia_gc_strdup(const char *s);

/**
 * @brief Duplicate a memory block using GC-tracked memory.
 */
void *portillia_gc_memdup(const void *src, size_t size);

/**
 * @brief Reallocate a GC-tracked block.
 *
 * If ptr is NULL, behaves like portillia_gc_alloc().
 * If new_size is 0, frees ptr and returns NULL.
 */
void *portillia_gc_realloc(void *ptr, size_t new_size);

/* ---------- Deallocation ---------- */

/**
 * @brief Deferred free using EBR.
 *
 * Safe to call even when other threads may still be reading the object.
 * The memory is retired to the current epoch and reclaimed once all
 * readers have exited that epoch.
 */
void portillia_gc_free_later(void *ptr);

/**
 * @brief Immediate free.
 *
 * Only safe when the caller knows no other thread can access ptr.
 * Unregisters the block from the GC tree before freeing.
 */
void portillia_gc_free(void *ptr);

/* ---------- Epoch / Reclaim ---------- */

/**
 * @brief Manually rotate the epoch and reclaim memory.
 *
 * Called automatically by the background rotator thread;
 * exposed for tests and shutdown sequences.
 */
void portillia_gc_rotate(void);
void portillia_gc_reclaim(void);

/* ---------- EBR critical sections ---------- */

/**
 * @brief Enter an EBR read-side critical section.
 *
 * Must be paired with portillia_gc_read_exit().
 * Used when traversing shared lock-free structures.
 */
static inline void portillia_gc_read_enter(void) {
    ttak_epoch_enter();
}

static inline void portillia_gc_read_exit(void) {
    ttak_epoch_exit();
}

/* ---------- Convenience macros ---------- */

#define PORTILLIA_GC_NEW(type) ((type *)portillia_gc_alloc(sizeof(type)))
#define PORTILLIA_GC_NEW_ZERO(type) ((type *)portillia_gc_calloc(1, sizeof(type)))

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_MEM_GC_H */
