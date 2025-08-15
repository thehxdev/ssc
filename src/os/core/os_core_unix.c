// Unix specific implementations

dl_handle_t os_dlopen(const char *path) {
    return dlopen(path, RTLD_LAZY);
}

void *os_dlsym(dl_handle_t handle, const char *symbol) {
    return dlsym(handle, symbol);
}

void os_dlclose(dl_handle_t handle) {
    dlclose(handle);
}

char *os_dlerror(void) {
    return dlerror();
}
