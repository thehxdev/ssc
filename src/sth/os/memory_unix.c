#ifdef __cplusplus
extern "C" {
#endif

void *sth_os_mem_reserve(size_t size, int with_large_pages) {
    int wlp = (with_large_pages) ? MAP_HUGETLB : 0;
    void *p = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | wlp, -1, 0);
    if (p == MAP_FAILED)
        p = NULL;
    return p;
}

int sth_os_mem_commit(void *p, size_t size, int with_large_pages) {
    (void)with_large_pages;
    return (mprotect(p, size, PROT_READ | PROT_WRITE) == 0);
}

void sth_os_mem_release(void *p, size_t size) {
    munmap(p, size);
}

size_t sth_os_get_pagesize(void) {
    return sysconf(_SC_PAGESIZE);
}

size_t sth_os_get_largepagesize(void) {
    // 2 MB is a safe value for Linux and most BSD systems
    return STH_BASE_MB(2);
}

#ifdef __cplusplus
}
#endif
