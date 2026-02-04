int ssc_socks5_validate_auth_methods(unsigned char *bytes, size_t size) {
    if (bytes[0] != SOCKS5_Version)
        return SSC_ERROR_SOCKS5_VERSION_MISMATCH;

    int nmethods = bytes[1], i;
    unsigned char *methods = &bytes[2];
    for (i = 0; i < nmethods; i++) {
        if (methods[i] == SOCKS5_NoAuth)
            break;
    }
    if (i == nmethods)
        return SSC_ERROR_SOCKS5_UNSUPPORTED_AUTH_METHOD;

    return SSC_OK;
}
