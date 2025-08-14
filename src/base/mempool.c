#include <stddef.h>
#include "arena.h"
#include "mempool.h"

union __mempool_chunk {
    __mempool_chunk_t *next;
};

void ssc_mempool_init(ssc_mempool_t *self, arena_t *arena, size_t chunk_size) {
    self->arena = arena;
    self->chunk_size = (chunk_size >= sizeof(__mempool_chunk_t)) ?
        chunk_size : sizeof(__mempool_chunk_t);
    self->freelist = NULL;
}

void *ssc_mempool_get(ssc_mempool_t *self) {
    __mempool_chunk_t *c;
    if (!self->freelist)
        return arena_alloc(self->arena, self->chunk_size);
    c = self->freelist;
    self->freelist = c->next;
    return c;
}

void ssc_mempool_put(ssc_mempool_t *self, void *v) {
    __mempool_chunk_t *c = (__mempool_chunk_t*) v;
    c->next = self->freelist;
    self->freelist = c;
}
