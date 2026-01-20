#ifdef __cplusplus
extern "C" {
#endif

sth_arena_t *sth_arena_new(sth_arena_config_t config) {
    sth_arena_t *a;
    size_t pagesize, reserve, commit;
    int lp = config.flags & STH_ARENA_LARGPAGES;

    pagesize = (lp) ? sth_os_get_largepagesize() : sth_os_get_pagesize();

    // align reserve and commit fields by operating system's page size
    reserve = sth_base_align_pow2(config.reserve, pagesize);
    commit = sth_base_align_pow2(config.commit, pagesize);

    a = STH_BASE_DECLTYPE(a) sth_os_mem_reserve(reserve, lp);
    if (!a)
        return NULL;

    if (!sth_os_mem_commit(a, commit, lp)) {
        sth_os_mem_release(a, reserve);
        return NULL;
    }

    memcpy(&a->config, &config, sizeof(config));

    // store aligned values
    a->config.reserve = reserve;
    a->config.commit  = commit;
    a->commited = commit;
    a->reserved = reserve;

    a->pos_base = 0;
    a->pos = STH_ARENA_HEADER_SIZE;
    a->prev = NULL;
    a->current = a;

    return a;
}

void *sth_arena_alloc_align(sth_arena_t *arena, size_t size, size_t alignment) {
    sth_arena_t *current, *new_arena;
    size_t pos_pre, pos_past;

    // assert that alignment is a power of 2
    STH_BASE_ASSERT((alignment & (alignment - 1)) == 0);

    // If size is zero or requested size is bigger than the arena's capacity, return NULL
    if (size == 0 || size > (arena->reserved - STH_ARENA_HEADER_SIZE))
        return NULL;

    current = arena->current;
    pos_pre = sth_base_align_pow2(current->pos, alignment);
    pos_past = pos_pre + size;

    if (pos_past > current->reserved) {
        if (current->config.flags & STH_ARENA_FIXED)
            return NULL;

        if ( !(new_arena = sth_arena_new(current->config)))
            return NULL;

        new_arena->pos_base = current->pos_base + current->reserved;
        new_arena->prev = current;
        arena->current = new_arena;

        // reinitialize allocation info
        current = new_arena;
        pos_pre = sth_base_align_pow2(current->pos, alignment);
        pos_past = pos_pre + size;
    }

    // commit new pages if needed
    if (pos_past > current->commited) {
        // Since "reserve" and "commit" fields in arena config are already
        // aligned by operating system's page size, the "commit" field is
        // divisible by "reserve" field. So we can divied the arena's buffer to
        // blocks with "commit" size each.
        size_t must_commit = current->commited;
        while (must_commit < pos_past) {
            must_commit += current->config.commit;
        }
        sth_os_mem_commit((unsigned char*)current + current->commited,
                          must_commit,
                          current->config.flags & STH_ARENA_LARGPAGES);
        current->commited = must_commit;
    }

    current->pos = pos_past;
    return ((unsigned char*)current + pos_pre);
}

size_t sth_arena_pos(const sth_arena_t *arena) {
    sth_arena_t *current = arena->current;
    return (current->pos_base + current->pos);
}

int sth_arena_is_empty(const sth_arena_t *arena) {
    return (sth_arena_pos(arena) == STH_ARENA_HEADER_SIZE);
}

void sth_arena_pop_to(sth_arena_t *arena, size_t pos) {
    size_t new_pos;
    sth_arena_t *current = arena->current, *prev;
    pos = (pos > STH_ARENA_HEADER_SIZE) ? pos : STH_ARENA_HEADER_SIZE;
    while (current->pos_base >= pos) {
        prev = current->prev;
        sth_os_mem_release(current, current->reserved);
        current = prev;
    }
    current->prev = NULL;
    arena->current = current;
    new_pos = pos - current->pos_base;
    STH_BASE_ASSERT(new_pos <= current->pos);
    current->pos = new_pos;
}

void sth_arena_pop(sth_arena_t *arena, size_t offset) {
    size_t curr_pos = sth_arena_pos(arena);
    if (offset <= curr_pos)
        sth_arena_pop_to(arena, curr_pos - offset);
}

void sth_arena_reset(sth_arena_t *arena) {
    sth_arena_pop_to(arena, 0);
}

void sth_arena_destroy(sth_arena_t *arena) {
    sth_arena_t *current, *prev;
    current = arena->current;
    while (current) {
        prev = current->prev;
        sth_os_mem_release(current, current->reserved);
        current = prev;
    }
}

void sth_arena_scope_begin(sth_arena_t *arena, sth_arena_scope_t *scope_out) {
    *scope_out = (sth_arena_scope_t){
        .arena = arena,
        .pos = sth_arena_pos(arena),
    };
}

void sth_arena_scope_end(sth_arena_scope_t *scope) {
    sth_arena_pop_to(scope->arena, scope->pos);
    *scope = (sth_arena_scope_t){
        .arena = NULL,
        .pos = 0,
    };
}

char *sth_arena_strndup(sth_arena_t *arena, const char *s, size_t size) {
    char *buf = STH_BASE_DECLTYPE(buf) sth_arena_alloc(arena, size + 1);
    STH_BASE_ASSERT(buf != NULL);
    memcpy(buf, s, size);
    buf[size] = 0;
    return buf;
}

#ifdef __cplusplus
}
#endif
