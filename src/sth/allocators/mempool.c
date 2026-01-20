#ifdef __cplusplus
extern "C" {
#endif

union sth_mempool_node {
    sth_mempool_node_t *next;
};

void sth_mempool_init(sth_mempool_t *self, sth_arena_t *arena, size_t size) {
    if (size < sizeof(sth_mempool_node_t))
        size = sizeof(sth_mempool_node_t);
    *self = (sth_mempool_t){
        .arena = arena,
        .list = NULL,
        .size = size
    };
}

void *sth_mempool_get(sth_mempool_t *self) {
    sth_mempool_node_t *c;
    if (!self->list)
        return sth_arena_alloc(self->arena, self->size);
    c = self->list;
    self->list = c->next;
    return c;
}

void sth_mempool_put(sth_mempool_t *self, void *v) {
    sth_mempool_node_t *c = STH_BASE_DECLTYPE(c) v;
    c->next = self->list;
    self->list = c;
}

#ifdef __cplusplus
}
#endif
