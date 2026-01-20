#ifdef __cplusplus
extern "C" {
#endif

char *sth_io_file_read_all(const char *path, size_t *out_file_size) {
    size_t file_size = 0, nread = 0;
    char *content = NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp)
        goto ret;

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    if (file_size == 0)
        goto ret_close_file;
    rewind(fp);

    content = STH_BASE_DECLTYPE(content) STH_BASE_MALLOC(file_size + 1);
    STH_BASE_ASSERT(content != NULL);

    nread = fread(content, sizeof(*content), file_size, fp);
    STH_BASE_ASSERT(file_size == nread);

    *out_file_size = file_size;
ret_close_file:
    fclose(fp);
ret:
    return content;
}

#ifdef __cplusplus
}
#endif
