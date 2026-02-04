#ifndef _STH_OS_FILESYSTEM_H_
#define _STH_OS_FILESYSTEM_H_

#ifdef __cplusplus
extern "C" {
#endif

int sth_os_file_size(const char *path, size_t *size_out);

int sth_os_file_exists(const char *path);

int sth_os_rename(const char *old_path, const char *new_path);

int sth_os_mkdir_if_not_exists(const char *path);

#ifdef __cplusplus
}
#endif

#endif // _STH_OS_FILESYSTEM_H_
