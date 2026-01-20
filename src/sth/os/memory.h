#ifdef __cplusplus
extern "C" {
#endif

void *sth_os_mem_reserve(size_t size, int with_large_pages);

int sth_os_mem_commit(void *p, size_t size, int with_large_pages);

void sth_os_mem_release(void *p, size_t size);

size_t sth_os_get_pagesize(void);

size_t sth_os_get_largepagesize(void);

#ifdef __cplusplus
}
#endif
