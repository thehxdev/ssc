#ifndef _STH_IO_IO_H_
#define _STH_IO_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

char *sth_io_file_read_all(const char *path, size_t *out_file_size);

#ifdef __cplusplus
}
#endif

#endif // _STH_IO_IO_H_
