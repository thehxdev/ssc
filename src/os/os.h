#ifndef _SSC_OS_H_
#define _SSC_OS_H_

#ifdef _WIN32
    #include "os/core/os_core_windows.h"
#else
    #include "os/core/os_core_unix.h"
#endif

#include "os/core/os_core.h"
#include "os/memory/arena.h"
#include "os/memory/mempool.h"

#endif // _SSC_OS_H_
