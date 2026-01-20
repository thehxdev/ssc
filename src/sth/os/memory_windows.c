#ifdef __cplusplus
extern "C" {
#endif

void *sth_os_mem_reserve(size_t size, int with_large_pages) {
    int wlp = (with_large_pages) ? (MEM_COMMIT | MEM_LARGE_PAGES) : 0;
    void *p = VirtualAlloc(NULL, size, MEM_RESERVE | wlp, PAGE_READWRITE);
    return p;
}

int sth_os_mem_commit(void *p, size_t size, int with_large_pages) {
    if (with_large_pages)
        return 1;
    return (VirtualAlloc(p, size, MEM_COMMIT, PAGE_READWRITE) != 0);
}

void sth_os_mem_release(void *p, size_t size) {
    (void)size;
    VirtualFree(p, 0, MEM_RELEASE);
}

size_t sth_os_get_pagesize(void) {
    SYSTEM_INFO sysinfo;
    memset(&sysinfo, 0, sizeof(sysinfo));
    GetSystemInfo(&sysinfo);
    return sysinfo.dwPageSize;
}

size_t sth_os_get_largepagesize(void) {
    return GetLargePageMinimum();
}

#ifdef __cplusplus
}
#endif
