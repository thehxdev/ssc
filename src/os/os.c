#ifdef _WIN32
    #include "os/core/os_core_windows.c"
#else
    #include "os/core/os_core_unix.c"
#endif

#include "os/core/os_core.c"
#include "os/memory/arena.c"
#include "os/memory/mempool.c"
