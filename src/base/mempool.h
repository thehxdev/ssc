#ifndef _SSC_MEMORY_POOL_H_
#define _SSC_MEMORY_POOL_H_

#include <stddef.h>
#include "arena.h"

typedef union __mempool_chunk __mempool_chunk_t;

typedef struct ssc_mempool {
    arena_t *arena;
    __mempool_chunk_t *freelist;
    size_t chunk_size;
} ssc_mempool_t;

void ssc_mempool_init(ssc_mempool_t *self, arena_t *arena, size_t chunk_size);

void *ssc_mempool_get(ssc_mempool_t *self);

void ssc_mempool_put(ssc_mempool_t *self, void *v);

void ssc_mempool_free(ssc_mempool_t *self);

#endif // _SSC_MEMORY_POOL_H_
