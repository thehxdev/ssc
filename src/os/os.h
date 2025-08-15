#ifndef _SSC_OS_H_
#define _SSC_OS_H_

#if defined(SSC_OS_UNIX)
    #include "os/core/os_core_unix.h"
#elif defined(SSC_OS_WINDOWS)
    #include "os/core/os_core_windows.h"
#endif

#include "os/core/os_core.h"

#endif // _SSC_OS_H_
