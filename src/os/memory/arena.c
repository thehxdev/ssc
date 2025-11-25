/*
 * Standalone and zero-dependency arena allocator implementation in C99.
 * Repository: https://github.com/thehxdev/arena
 *
 * The implementation is mostly inspired by the arena implementation in
 * https://github.com/EpicGamesExt/raddebugger project (MIT License).
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include "arena.h"

#define ARENA_INITIAL_POS   sizeof(arena_t)

// align up a number to a power-of-2 alignment
#define arena_align_pow2(num, alignment) \
    ((((arena_uintptr_t)num) + ((alignment) - 1)) & (~((alignment) - 1)))

// static_assert implementation in C89 and C99!
// Learned this from "https://github.com/EpicGamesExt/raddebugger"
#define __arena_concat_(A,B) A##B
#define __arena_concat(A,B) __arena_concat_(A,B)
#define __arena_static_assert(condition, id) \
    extern char __arena_concat(id, __LINE__)[ ((condition)) ? 1 : -1 ]

// validate that `arena_uintptr_t` can hold a pointer
__arena_static_assert((sizeof(arena_uintptr_t) == sizeof(void*)), validate_uintptr_size);


#if defined(__linux__) /* linux */ \
    || (defined(__APPLE__) && defined(__MACH__)) /* apple */ \
    || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) /* bsd */

    // unix-like platforms
    #define ARENA_PLAT_UNIX
    #include <sys/mman.h>
    #include <unistd.h>

#elif defined(_WIN32) || defined(_WIN64)

    // windows platform
    #define ARENA_PLAT_WINDOWS
    #include <windows.h>
    #include <memoryapi.h>
    #include <sysinfoapi.h>

#else // not unix-like nor windows
    #error "unsupported platform"
#endif

// ask operating system for memory
static void *arena_os_reserve(arena_size_t size, int with_large_pages) {
    void *p; int wlp;
#ifdef ARENA_PLAT_UNIX
    wlp = (with_large_pages) ? MAP_HUGETLB : 0;
    p = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | wlp, -1, 0);
    if (p == MAP_FAILED)
        p = NULL;
#else
    wlp = (with_large_pages) ? (MEM_COMMIT | MEM_LARGE_PAGES) : 0;
    p = VirtualAlloc(NULL, size, MEM_RESERVE | wlp, PAGE_READWRITE);
#endif
    return p;
}

// commit a page (prepare it for read/write)
static int arena_os_commit(void *p, arena_size_t size, int with_large_pages) {
#ifdef ARENA_PLAT_UNIX
    (void)with_large_pages;
    return (mprotect(p, size, PROT_READ | PROT_WRITE) == 0);
#else
    if (with_large_pages)
        return 1;
    return (VirtualAlloc(p, size, MEM_COMMIT, PAGE_READWRITE) != 0);
#endif
}

// release an reserved memory block
static void arena_os_release(void *p, arena_size_t size) {
#ifdef ARENA_PLAT_UNIX
    munmap(p, size);
#else
    (void)size;
    VirtualFree(p, 0, MEM_RELEASE);
#endif
}

static inline arena_size_t arena_os_get_pagesize(void) {
#ifdef ARENA_PLAT_UNIX
    return sysconf(_SC_PAGESIZE);
#else
    SYSTEM_INFO sysinfo;
    memset(&sysinfo, 0, sizeof(sysinfo));
    GetSystemInfo(&sysinfo);
    return sysinfo.dwPageSize;
#endif
}

static inline arena_size_t arena_os_get_largepagesize(void) {
#ifdef ARENA_PLAT_UNIX
    // 2 MB is a safe value for Linux and most BSD systems
    return ARENA_MB(2);
#else
    return GetLargePageMinimum();
#endif
}

arena_t *arena_new(const arena_config_t *config) {
    arena_t *a;
    arena_size_t pagesize, reserve, commit;
    int lp = config->flags & ARENA_LARGPAGES;

    pagesize = (lp) ? arena_os_get_largepagesize() : arena_os_get_pagesize();

    // align reserve and commit fields by operating system's page size
    reserve = arena_align_pow2(config->reserve, pagesize);
    commit = arena_align_pow2(config->commit, pagesize);

    a = (arena_t*) arena_os_reserve(reserve, lp);
    if (!a)
        return NULL;
    if (!arena_os_commit(a, commit, lp)) {
        arena_os_release(a, reserve);
        return NULL;
    }

    memcpy(&a->config, config, sizeof(*config));

    // store aligned values
    a->config.reserve = reserve;
    a->config.commit  = commit;
    a->commited = commit;
    a->reserved = reserve;

    a->pos_base = 0;
    a->pos = ARENA_INITIAL_POS;
    a->prev = NULL;
    a->current = a;

    return a;
}

void *arena_alloc_align(arena_t *arena, arena_size_t size, arena_size_t alignment) {
    unsigned char *raw, *aligned;
    arena_t *current, *new_arena;
    arena_size_t padding;

    // If size is zero or requested size is bigger than the arena return NULL
    if (size == 0 || size > (arena->reserved - sizeof(*arena)))
        return NULL;

    current = arena->current;
    raw = (unsigned char*)current + current->pos;
    aligned = (unsigned char*) arena_align_pow2(raw, alignment);
    padding = aligned - raw;

    if ((size + padding) > (current->reserved - current->pos)) {
        if (current->config.flags & ARENA_FIXED)
            return NULL;

        if ( !(new_arena = arena_new(&current->config)))
            return NULL;

        new_arena->pos_base = current->pos_base + current->reserved;
        new_arena->prev = current;
        arena->current = new_arena;

        // reinitialize allocation info
        current = new_arena;
        raw = (unsigned char*)current + current->pos;
        aligned = (unsigned char*) arena_align_pow2(raw, alignment);
        padding = aligned - raw;
    }
    current->pos += size + padding;

    // commit new pages if needed
    if (current->pos > current->commited) {
        // Since "reserve" and "commit" fields in arena config are already
        // aligned by operating system's page size, the "commit" field is
        // divisible by "reserve" field. So we can divied the arena's buffer to
        // blocks with "commit" size each.
        arena_os_commit((unsigned char*)current + current->commited,
                        current->config.commit,
                        current->config.flags & ARENA_LARGPAGES);
        current->commited += current->config.commit;
    }

    return aligned;
}

arena_size_t arena_pos(const arena_t *arena) {
    return (arena->current->pos_base + arena->current->pos);
}

int arena_is_empty(const arena_t *arena) {
    return ((arena->current->pos_base == 0) && (arena->pos == ARENA_INITIAL_POS));
}

void arena_pop_to(arena_t *arena, arena_size_t pos) {
    arena_t *current = arena->current, *prev = NULL;
    while (current->pos_base >= pos) {
        prev = current->prev;
        arena_os_release(current, current->reserved);
        current = prev;
    }
    arena->current = current;
    current->pos = pos - current->pos_base;
}

void arena_pop(arena_t *arena, arena_size_t offset) {
    arena_size_t curr_pos = arena_pos(arena);
    if (offset <= curr_pos)
        arena_pop_to(arena, curr_pos - offset);
}

void arena_reset(arena_t *arena) {
    arena_pop_to(arena, ARENA_INITIAL_POS);
}

void arena_destroy(arena_t *arena) {
    arena_t *current, *prev;
    current = arena->current;
    while (current) {
        prev = current->prev;
        arena_os_release(current, current->reserved);
        current = prev;
    }
}

void arena_scope_begin(arena_t *arena, arena_scope_t *scope_out) {
    *scope_out = (arena_scope_t){
        .arena = arena,
        .pos = arena_pos(arena),
    };
}

void arena_scope_end(arena_scope_t *scope) {
    arena_pop_to(scope->arena, scope->pos);
    *scope = (arena_scope_t){
        .arena = NULL,
        .pos = ARENA_INITIAL_POS,
    };
}

#ifdef __cplusplus
}
#endif
