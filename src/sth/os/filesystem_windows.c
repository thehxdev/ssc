#ifdef __cplusplus
extern "C" {
#endif

int sth_os_file_exists(const char *path) {
    DWORD dwAttrib = GetFileAttributesA(path);
    return dwAttrib != INVALID_FILE_ATTRIBUTES;
}

int sth_os_rename(const char *old_path, const char *new_path) {
    if (MoveFileEx(old_path, new_path, MOVEFILE_REPLACE_EXISTING) == 0) {
        return STH_FAILED;
    }
    return STH_OK;
}

int sth_os_mkdir_if_not_exists(const char *path) {
    BOOL res = (int)CreateDirectory(path, NULL);
    if (!res) {
        int err = GetLastError();
        if (err == ERROR_ALREADY_EXISTS)
            return STH_OK;
        return STH_FAILED;
    }
    return STH_OK;
}

#ifdef __cplusplus
}
#endif
