#ifndef _SSC_OS_CORE_UNIX_H_
#define _SSC_OS_CORE_UNIX_H_

#include <time.h>
#include <unistd.h>
#include <endian.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/mman.h>

// dynamic library handle
typedef void* dl_handle_t;

#endif // _SSC_OS_CORE_UNIX_H_
