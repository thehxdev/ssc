#ifndef _SSC_BASE_BASE_H_
#define _SSC_BASE_BASE_H_

#define unused(v) ((void)(v))

// align up a number to a power-of-2 alignment
#define ALIGN_POW2(num, alignment) \
    ((((arena_uintptr_t)num) + ((alignment) - 1)) & (~((alignment) - 1)))

// static_assert implementation in C89 and C99!
// Learned this from "https://github.com/EpicGamesExt/raddebugger"
#define ssc_concat_(A,B) A##B
#define ssc_concat(A,B) ssc_concat_(A,B)
#define ssc_static_assert(condition, id) \
    extern char ssc_concat(id, __LINE__)[ ((condition)) ? 1 : -1 ]

#endif // _SSC_BASE_BASE_H_
