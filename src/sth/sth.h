#ifndef _STH_H_
#define _STH_H_

#define STH_VERSION_MAJOR 0
#define STH_VERSION_MINOR 5
#define STH_VERSION_PATCH 0
#define STH_VERSION_STRING "0.5.0"

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
    #error "At least C99 standard is required"
#endif

#ifdef _WIN32
    #define _CRT_SECURE_NO_WARNINGS (1)
#endif

#if defined(__linux__) /* linux */ \
    || (defined(__APPLE__) && defined(__MACH__)) /* apple */ \
    || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) /* bsd */
    // unix-like platforms
    #define STH_PLATFORM_UNIX
#elif defined(_WIN32) || defined(_WIN64)
    // windows platform
    #define STH_PLATFORM_WINDOWS
#else
    // not unix-like nor windows
    #error "unsupported platform"
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>

#ifdef STH_PLATFORM_UNIX
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>
#else
    #include <memoryapi.h>
    #include <sysinfoapi.h>
    #include <windows.h>
#endif

#include "base/base.h"
#include "os/os.h"
#include "ds/ds.h"
#include "io/io.h"
#include "encoding/encoding.h"
#include "allocators/allocators.h"

#endif // _STH_H_
