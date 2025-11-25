#ifndef _SSC_OS_CORE_H_
#define _SSC_OS_CORE_H_

dl_handle_t os_dlopen(const char *path);

void *os_dlsym(dl_handle_t handle, const char *symbol);

void os_dlclose(dl_handle_t handle);

char *os_dlerror(void);

#endif // _SSC_OS_CORE_H_
