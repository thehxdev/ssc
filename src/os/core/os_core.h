#ifndef _SSC_OS_CORE_H_
#define _SSC_OS_CORE_H_

// Common STD C headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>


dl_handle_t os_dlopen(const char *path);

void *os_dlsym(dl_handle_t handle, const char *symbol);

void os_dlclose(dl_handle_t handle);

char *os_dlerror(void);

#endif // _SSC_OS_CORE_H_
