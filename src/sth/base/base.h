#ifndef _STH_BASE_BASE_H_
#define _STH_BASE_BASE_H_

#ifdef __cplusplus
    #define STH_BASE_DECLTYPE(T) (decltype(T))
#else
    #define STH_BASE_DECLTYPE(T)
#endif

enum {
    STH_FAILED,
    STH_OK,
};

#define STH_BASE_KB(value) ((value) * 1024)
#define STH_BASE_MB(value) (STH_BASE_KB(value) * 1024)
#define STH_BASE_GB(value) (STH_BASE_MB(value) * 1024)

#define STH_BASE_MALLOC(s)       malloc((s))
#define STH_BASE_CALLOC(n, s)    calloc((n), (s))
#define STH_BASE_REALLOC(p, s)   realloc((p), (s))
#define STH_BASE_FREE(p)         free((p))
#define STH_BASE_ASSERT(c)       assert((c))

#define STH_BASE_ARRAY_LEN(a) (sizeof((a)) / sizeof((a)[0]))

#define STH_BASE_TIME_SPENT_MS(__elapsed_var, __block) \
    do { \
        clock_t __clock_start; \
        __clock_start = clock(); \
        do { __block; } while (0); \
        __elapsed_var = ((double)(clock() - __clock_start)) * 1000.0 / CLOCKS_PER_SEC; \
    } while (0)

#define sth_base_offsetof(T, F) (&((T*)NULL)->F)
#ifndef offsetof
    #define offsetof sth_base_offsetof
#endif

// Branch prediction hints
#if defined(__clang__) || defined(__GNUC__)
    #define STH_BASE_EXPECT(expr, val) __builtin_expect((expr), (val))
#else
    #define STH_BASE_EXPECT(expr, val) (expr)
#endif
#define STH_BASE_LIKELY(expr)    STH_BASE_EXPECT(expr, 1)
#define STH_BASE_UNLIKELY(expr)  STH_BASE_EXPECT(expr, 0)


// Compiler specific macros
#if defined(__GNUC__) || defined(__clang__)
    #define STH_BASE_TRAP() __builtin_trap()
    #define STH_BASE_PACKED(__decl__) __decl__ __attribute__((packed))
#elif defined (_MSC_VER)
    #define STH_BASE_TRAP() __debugbreak()
    #define STH_BASE_PACKED(__decl__) __pragma(pack(push, 1)) __decl__ __pragma(pack(pop))
#else
    #define STH_BASE_TRAP() (*(volatile char*)0)
#endif


#if defined(NDEBUG)
    #define sth_base_assert(cond)   (NULL)
    #define sth_base_trap_assert(cond)  (NULL)
#else
    #define sth_base_assert(cond) \
        do { \
            if (!(cond)) { \
                fprintf(stderr, "%s(%d): sth_base_assert(" #cond ") failed\n", __FILE__, __LINE__); \
                abort(); \
            } \
        } while (0)

    #define sth_base_trap_assert(cond) \
        do { \
            if (!(cond)) { \
                fprintf(stderr, "%s(%d): sth_base_trap_assert(" #cond ") failed\n", __FILE__, __LINE__); \
                STH_BASE_TRAP(); \
            } \
        } while (0)
#endif

#define __sth_base_stringify_(A) #A
#define sth_base_stringify(A) __sth_base_stringify_(A)

#define __sth_base_concat_(A,B) A##B
#define sth_base_concat(A,B) __sth_base_concat_(A,B)

#if __STDC_VERSION__ >= 202311L
    #define sth_base_static_assert(condition, id) \
        static_assert(condition, sth_base_stringify(id))
#elif __STDC_VERSION__ >= 201112L && __STDC_VERSION__ < 202311L
    #define sth_base_static_assert(condition, id) \
        _Static_assert(condition, sth_base_stringify(id))
#else
    #define sth_base_static_assert(condition, id) \
        char sth_base_concat(id, __LINE__)[ ((condition)) ? 1 : -1 ]
#endif

// Change byte order of a numeric value
#define sth_base_bswap16(x) ((((x) << 8) & 0xff00)  | (((x) >> 8) & 0x00ff))
#define sth_base_bswap32(x) (sth_base_bswap16(x) << 16 | sth_base_bswap16((x) >> 16))
#define sth_base_bswap64(x) (sth_base_bswap32(x) << 32 | sth_base_bswap32((x) >> 32))

// align up a number to a power-of-2 alignment
#define sth_base_align_pow2(num, alignment) \
    ((((uintptr_t)num) + ((alignment) - 1)) & (~((alignment) - 1)))

#include "stb_sprintf.h"

#endif // _STH_BASE_BASE_H_
