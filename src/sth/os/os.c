#ifdef STH_PLATFORM_UNIX
    #include "memory_unix.c"
#else
    #include "memory_windows.c"
#endif

#ifdef STH_PLATFORM_UNIX
    #include "filesystem_unix.c"
#else
    #include "filesystem_windows.c"
#endif
