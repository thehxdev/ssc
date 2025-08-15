// Windows specific implementations

dl_handle_t os_dlopen(const char *path) {
    return LoadLibrary(dlpath);
}

void *os_dlsym(dl_handle_t handle, const char *symbol) {
    return GetProcAddress(handle, symbol);
}

void os_dlclose(dl_handle_t handle) {
    FreeLibrary(handle);
}
