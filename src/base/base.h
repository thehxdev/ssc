#ifndef _SSC_BASE_BASE_H_
#define _SSC_BASE_BASE_H_

#define SSC_UNUSED(v) ((void)(v))

#if defined(__GNUC__) || defined(__clang__)
    #define SSC_TRAP __builtin_trap()
    #define SSC_PACKED(__decl__) __decl__ __attribute__((packed))
#elif defined (_MSC_VER)
    #define SSC_TRAP __debugbreak()
    #define SSC_PACKED(__decl__) __pragma(pack(push, 1)) __decl__ __pragma(pack(pop))
#else
    #define SSC_TRAP (*(volatile char*)0)
#endif

#if defined(NDEBUG) || (defined(BUILD_DEBUG) && BUILD_DEBUG == 0)
    #define trap_assert(cond)
#else
    #define trap_assert(cond) \
        do { \
            if (!(cond)) { \
                fprintf(stderr, "%s(%d): trap_assert(" #cond ")", __FILE__, __LINE__); \
                SSC_TRAP; \
            } \
        } while (0)
#endif

// static_assert implementation in C89 and C99!
// Learned this from "https://github.com/EpicGamesExt/raddebugger"
#define ssc_concat_(A,B) A##B
#define ssc_concat(A,B) ssc_concat_(A,B)
#define ssc_static_assert(condition, id) \
    extern char ssc_concat(id, __LINE__)[ ((condition)) ? 1 : -1 ]

// Change byte order of a numeric value
#define ssc_bswap16(x) ((((x) << 8) & 0xff00)  | (((x) >> 8) & 0x00ff))
#define ssc_bswap32(x) (ssc_bswap16(x) << 16 | ssc_bswap16((x) >> 16))
#define ssc_bswap64(x) (ssc_bswap32(x) << 32 | ssc_bswap32((x) >> 32))

#endif // _SSC_BASE_BASE_H_
