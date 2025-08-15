#define __dlsym_ex(handle, name) \
    tmp = os_dlsym((handle), (name)); \
    if (!tmp) \
        goto ret_close_handle;

int ssc_config_readall(arena_t *arena, const char *dlpath, struct ssc_config *config) {
    int ok = 0, i;
    void *handle, *tmp;
    handle = os_dlopen(dlpath);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        goto ret;
    }

    // dont want to keep the dynamic library open so I used strdup
    // to keep pointer's data and close dynamic library.
    const char *strs[_CONFIG_SF_COUNT] = {
        [CONFIG_LISTEN_ADDR] = "listen_addr",
        [CONFIG_REMOTE_ADDR] = "remote_addr",
        [CONFIG_METHOD] = "method",
        [CONFIG_PASSWORD] = "password",
    };
    for (i = 0; i < _CONFIG_SF_COUNT; ++i) {
        __dlsym_ex(handle, strs[i]);
        config->sf[i] = arena_alloc(arena, strlen(tmp)+1);
        strcpy(config->sf[i], tmp);
    }

    __dlsym_ex(handle, "listen_port");
    config->listen_port = *(uint16_t*)tmp;

    __dlsym_ex(handle, "remote_port");
    config->remote_port = *(uint16_t*)tmp;

    ok = 1;
ret_close_handle:
    os_dlclose(handle);
ret:
    return ok;
}
