#if defined(SSC_OS_UNIX)
    #include "os/core/os_core_unix.c"
#elif defined(SSC_OS_WINDOWS)
    #include "os/core/os_core_windows.c"
#endif

#include "os/core/os_core.c"
