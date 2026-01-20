#ifndef _STH_ALLOCATORS_ARENA_H_
#define _STH_ALLOCATORS_ARENA_H_

#ifdef __cplusplus
extern "C" {
#endif

#define sth_arena_alloc(arena, size) \
    sth_arena_alloc_align((arena), (size), (arena)->config.alignment)

#define STH_ARENA_DEFAULT_ALIGNMENT     (sizeof(void*) << 1)
#define STH_ARENA_DEFAULT_RESERVE_SIZE  STH_BASE_MB(16)
#define STH_ARENA_DEFAULT_COMMIT_SIZE   STH_BASE_KB(16)

#define STH_ARENA_DEFAULT_CONFIG \
    ((sth_arena_config_t){ \
        .reserve = STH_ARENA_DEFAULT_RESERVE_SIZE, \
        .commit = STH_ARENA_DEFAULT_COMMIT_SIZE, \
        .alignment = STH_ARENA_DEFAULT_ALIGNMENT, \
        .flags = STH_ARENA_NONE \
    })

enum {
    STH_ARENA_NONE = 0,
    // arena will be fixed in size and not grow in case of space limitation
    STH_ARENA_FIXED = (1 << 0),
    // use large pages
    STH_ARENA_LARGPAGES = (1 << 1),
};

typedef struct sth_arena_config {
    // the "reserve" and "commit" fields will be aligned by operating system's
    // page size
    size_t reserve, commit, alignment, flags;
} sth_arena_config_t;

typedef struct sth_arena {
    // all the fields are read-only to the user
    sth_arena_config_t config;
    struct sth_arena *prev, *current;
    // the "pos_base" field helps to track all the memory allocated and helps
    // to view the arena as a single buffer even with multiple buffers
    size_t pos, pos_base, reserved, commited;
} sth_arena_t;

// by using scopes you can take a snapshot from an existing arena, use that and
// restore the old state.
typedef struct sth_arena_scope {
    sth_arena_t *arena;
    size_t pos;
} sth_arena_scope_t;

#define STH_ARENA_HEADER_SIZE   (128)
sth_base_static_assert((sizeof(sth_arena_t) <= STH_ARENA_HEADER_SIZE), validate_sth_arena_header_size);

sth_arena_t *sth_arena_new(sth_arena_config_t config);

void *sth_arena_alloc_align(sth_arena_t *arena, size_t size, size_t alignment);

size_t sth_arena_pos(const sth_arena_t *arena);

int sth_arena_is_empty(const sth_arena_t *arena);

void sth_arena_pop_to(sth_arena_t *arena, size_t pos);

void sth_arena_pop(sth_arena_t *arena, size_t offset);

void sth_arena_reset(sth_arena_t *arena);

void sth_arena_destroy(sth_arena_t *arena);

void sth_arena_scope_begin(sth_arena_t *arena, sth_arena_scope_t *scope_out);

void sth_arena_scope_end(sth_arena_scope_t *scope);

char *sth_arena_strndup(sth_arena_t *arena, const char *s, size_t size);

#ifdef __cplusplus
}
#endif

#endif // _STH_ALLOCATORS_ARENA_H_
