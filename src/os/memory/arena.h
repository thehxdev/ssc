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

#ifndef _ARENA_H_
#define _ARENA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define arena_intptr_t  intptr_t
#define arena_uintptr_t uintptr_t
#define arena_size_t    size_t

#ifndef ARENA_DEFAULT_ALIGNMENT
    #define ARENA_DEFAULT_ALIGNMENT sizeof(arena_uintptr_t)
#endif

enum {
    ARENA_NONE = 0,
    // arena will be fixed in size and not grow in case of space limitation
    ARENA_FIXED = (1 << 0),
    // use large pages
    ARENA_LARGPAGES = (1 << 1),
};

typedef struct arena_config {
    // the "reserve" and "commit" fields will be aligned by operating system's
    // page size
    arena_size_t reserve, commit, alignment, flags;
} arena_config_t;

typedef struct arena {
    // all the fields are read-only to the user
    arena_config_t config;
    struct arena *prev, *current;
    // the "pos_base" field helps to track all the memory allocated and helps
    // to view the arena as a single buffer even with multiple buffers
    arena_size_t pos, pos_base, reserved, commited;
} arena_t;

// by using scopes you can take a snapshot from an existing arena, use that and
// restore the old state.
typedef struct arena_scope {
    arena_t *arena;
    arena_size_t pos; // read-only
} arena_scope_t;

#define ARENA_KB(value) ((value) * 1024)
#define ARENA_MB(value) (ARENA_KB(value) * 1024)
#define ARENA_GB(value) (ARENA_MB(value) * 1024)

#define ARENA_DEFAULT_RESERVE_SIZE ARENA_MB(16)
#define ARENA_DEFAULT_COMMIT_SIZE  ARENA_KB(16)

#define ARENA_DEFAULT_CONFIG \
    ((arena_config_t){ \
        .reserve = ARENA_DEFAULT_RESERVE_SIZE, \
        .commit = ARENA_DEFAULT_COMMIT_SIZE, \
        .alignment = ARENA_DEFAULT_ALIGNMENT, \
        .flags = ARENA_NONE \
    })

arena_t *arena_new(const arena_config_t *config);

void arena_destroy(arena_t *arena);

// Allocate memory on arena with specified alignment. The alignment value  MUST
// be a power of 2
void *arena_alloc_align(arena_t *arena, arena_size_t size, arena_size_t alignment);

// Helper macro to use arena's alignment value for allocations
#define arena_alloc(arena, size) \
    arena_alloc_align((arena), (size), (arena)->config.alignment)

// Is arena empty?
int arena_is_empty(const arena_t *arena);

// Get total bytes allocated
arena_size_t arena_pos(const arena_t *arena);

// Set arena's position to a position specified by pos
void arena_pop_to(arena_t *arena, arena_size_t pos);

// Seek back arena's pointer by offset.
void arena_pop(arena_t *arena, arena_size_t offset);

// Reset the arena. If the arena had more that one buffer, free all of them and
// just keep the first buffer and also reset that.
void arena_reset(arena_t *arena);

// Take a snapshot from an arena, use that and restore the old state with
// arena_scope_end function. This function writes data to scope_out.
void arena_scope_begin(arena_t *arena, arena_scope_t *scope_out);

// Restore an arena's state from an snapshot.
void arena_scope_end(arena_scope_t *scope);

#ifdef __cplusplus
}
#endif

#endif // _ARENA_H_
