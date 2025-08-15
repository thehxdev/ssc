#ifndef _SSC_OS_CORE_WINDOWS_H_
#define _SSC_OS_CORE_WINDOWS_H_

#include <windows.h>
#include <winsock2.h>
#include <memoryapi.h>

typedef HINSTANCE dl_handle_t;

dl_handle_t os_dlopen(const char *path);

#endif // _SSC_OS_CORE_WINDOWS_H_
