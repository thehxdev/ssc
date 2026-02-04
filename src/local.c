#define SSC_LISTEN_BACKLOG  128

#ifdef STH_PLATFORM_UNIX
    #define DEFAULT_CONFIG_PATH "./config.json"
#else
    #define DEFAULT_CONFIG_PATH ".\\config.json"
#endif

static sth_arena_t *arena;
static sth_mempool_t session_pool, wrreq_pool;

static ssc_sockaddr_in laddr, raddr;

static ssc_crypto_cipher *cipher;
static ssc_byte_t key[AES_MAX_KEY_SIZE];
static ssc_byte_t keysize;

static uv_loop_t *loop = NULL;

static size_t tx = 0, rx = 0;

// no-operation callback
static void noop_cb(void) {}

static void remote_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *rdbuf);
static void client_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *rdbuf);
static void remote_connect_cb(uv_connect_t *req, int status);

// allocate a buffer for libuv's "read" callbacks
static void buf_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = malloc(suggested_size);
    buf->len  = suggested_size;
}

static void conn_close_cb(uv_handle_t *handle) {
    ssc_conn_t *conn = (ssc_conn_t*)handle;
    ssc_session_t *s = conn->session;
    ssc_session_unref(s);
    if (s->refcount == 0) {
        if (s->tmpbuf.base)
            free(s->tmpbuf.base);
        ssc_crypto_deinit(&s->crypto);
        sth_mempool_put(&session_pool, s);
    }
}

static void conn_check_cb(uv_check_t *handle) {
    ssc_conn_t *conn = uv_handle_get_data((uv_handle_t*)handle);
    if (uv_stream_get_write_queue_size((uv_stream_t*)conn) == 0) {
        uv_check_stop(handle);
        uv_close((uv_handle_t*)conn, conn_close_cb);
    }
}

static void conn_write_cb(uv_write_t *req, int status) {
    ssc_write_t *wrreq = (ssc_write_t*) req;
    free(wrreq->buf.base);
    sth_mempool_put(&wrreq_pool, wrreq);
}

static void socks_reply_write_cb(uv_write_t *req, int status) {
    sth_mempool_put(&wrreq_pool, (ssc_write_t*)req);
}

static int client_socks5_method_selection(uv_stream_t *stream,
                                          ssize_t nread,
                                          const uv_buf_t *rdbuf)
{
    ssc_conn_t *client = (ssc_conn_t*)stream;

    ssc_write_t *wrreq = sth_mempool_get(&wrreq_pool);
    wrreq->buf = (uv_buf_t){
        .base = malloc(2),
        .len = 2,
    };
    wrreq->buf.base[0] = SOCKS5_Version;

    switch (ssc_socks5_validate_auth_methods(rdbuf->base, nread)) {
        case SSC_ERROR_SOCKS5_VERSION_MISMATCH:
            {
                uv_close((uv_handle_t*)client, conn_close_cb);
                LOGE(SSC_ADDRSTR_FMT " socks5 version mismatch\n", SSC_ADDRSTR_ARGS(client));
                return SSC_ERROR_SOCKS5_HANDSHAKE_FAILED;
            }
            break;

        case SSC_ERROR_SOCKS5_UNSUPPORTED_AUTH_METHOD:
            {
                wrreq->buf.base[1] = SOCKS5_NoAcceptableMethods;
                uv_write((uv_write_t*)wrreq, (uv_stream_t*)client, &wrreq->buf, 1, conn_write_cb);
                ssc_conn_set_closing(loop, client, conn_check_cb);
                LOGE(SSC_ADDRSTR_FMT " unsupported auth method\n", SSC_ADDRSTR_ARGS(client));
                return SSC_ERROR_SOCKS5_HANDSHAKE_FAILED;
            }
            break;
    }

    wrreq->buf.base[1] = SOCKS5_NoAuth;
    uv_write((uv_write_t*)wrreq, (uv_stream_t*)client, &wrreq->buf, 1, conn_write_cb);

    return SSC_OK;
}

static int client_socks5_prepare_reply(uv_stream_t *stream, ssize_t nread, const uv_buf_t *rdbuf) {
    ssc_conn_t *client = (ssc_conn_t*)stream;
    ssc_session_t *s = client->session;
    const ssc_byte_t reply_head[4] = {SOCKS5_Version, SOCKS5_Ok, SOCKS5_Reserved, SOCKS5_ATYPE_IPV4};

    long ptr = 0;
    memcpy(&s->socksreply[ptr], reply_head, sizeof(reply_head));
    ptr += sizeof(reply_head);

    memcpy(&s->socksreply[ptr], &laddr.sin_addr.s_addr, 4);
    ptr += 4;

    memcpy(&s->socksreply[ptr], &laddr.sin_port, 2);
    ptr += 2;

    if (rdbuf->base[1] != SOCKS5_Connect) {
        s->socksreply[1] = SOCKS5_CommandNotSupported;

        ssc_write_t *wrreq = sth_mempool_get(&wrreq_pool);
        wrreq->buf = (uv_buf_t){
            .base = s->socksreply,
            .len = ptr,
        };

        uv_write((uv_write_t*)wrreq, (uv_stream_t*)client, &wrreq->buf, 1, conn_write_cb);
        ssc_conn_set_closing(loop, client, conn_check_cb);
        return SSC_ERROR_SOCKS5_HANDSHAKE_FAILED;
    }

    // Save destination address requested by the client and delegate
    // DNS resolution to the Shadowsocks server. This information will
    // be used in the handshake with Shadowsocks server and since the
    // address format in Shadowsocks client handshake is same as the
    // socks5 one, we can copy this address directly to handshake
    // buffer.
    memcpy(s->dest.addr, &rdbuf->base[3], nread - 3);
    s->dest.size = nread - 3;

    switch (s->dest.addr[0]) {
        case SOCKS5_ATYPE_IPV4:
            {
                uv_inet_ntop(AF_INET, &s->dest.addr[1], s->dest.addrstr, sizeof(s->dest.addrstr));
                s->dest.port = ntohs(*(uint16_t*)&s->dest.addr[5]);
            }
            break;

        case SOCKS5_ATYPE_IPV6:
            {
                uv_inet_ntop(AF_INET6, &s->dest.addr[1], s->dest.addrstr, sizeof(s->dest.addrstr));
                s->dest.port = ntohs(*(uint16_t*)&s->dest.addr[17]);
            }
            break;

        case SOCKS5_ATYPE_FQDN:
            {
                const size_t len = s->dest.addr[1];
                memcpy(s->dest.addrstr, &s->dest.addr[2], len);
                s->dest.port = ntohs(*(uint16_t*)&s->dest.addr[2 + len]);
            }
            break;
    }

    ssc_conn_t *remote = client->dest;
    {
        // Initialize remote
        uv_tcp_init(loop, (uv_tcp_t*)remote);
        remote->session = ssc_session_ref(s);
    }

    // FIXME: add a timer to catch connection timeout to remote server
    uv_tcp_connect(&s->conreq, (uv_tcp_t*)remote, (ssc_sockaddr*)&raddr, remote_connect_cb);
    uv_read_stop((uv_stream_t*)client);

    return SSC_OK;
}

static int client_ss_handshake(uv_stream_t *stream, ssize_t nread, const uv_buf_t *rdbuf) {
    int vheader_length, ok;
    uint16_t padding_length;
    size_t encrypted_size;
    bool with_initial_payload = true;
    ssc_conn_t *client = (ssc_conn_t*)stream;
    ssc_session_t *s = client->session;

    ssc_write_t *wrreq = sth_mempool_get(&wrreq_pool);
    wrreq->buf = (uv_buf_t){
        .base = malloc(SSC_FULL_CHUNK_SIZE),
        .len  = 0,
    };

    memcpy(wrreq->buf.base, s->salt, keysize);
    wrreq->buf.len += keysize;

    {
        //////
        // begin fixed-length header
        //////
        ssc_fixed_header_t fixed_header;

        // set fixed-length header's type.
        // request streams has type 0.
        fixed_header.type = 0;

        // big endian timestamp
        fixed_header.timestamp = sth_base_bswap64((uint64_t)time(NULL));

        // set length field (variable-length header length) in fixed-length header
        padding_length = (random() % SSC_MAX_PADDING_SIZE) + 1;
        vheader_length = s->dest.size + sizeof(uint16_t) + padding_length + nread;

        // This is a rare case
        if (vheader_length > UINT16_MAX) {
            with_initial_payload = false;
            vheader_length -= nread;
        }

        fixed_header.length = htons((uint16_t)vheader_length);

        // encrypt and write fixed-length header and it's tag to request buffer
        ok = ssc_crypto_encrypt(&s->crypto,
                                &wrreq->buf.base[wrreq->buf.len], &encrypted_size,
                                &wrreq->buf.base[wrreq->buf.len + sizeof(fixed_header)], CRYPTO_TAG_SIZE,
                                &fixed_header, sizeof(fixed_header),
                                NULL, 0);
        assert(ok);
        assert(encrypted_size == sizeof(fixed_header));
        wrreq->buf.len += sizeof(fixed_header) + CRYPTO_TAG_SIZE;
        //////
        // end fixed-length header
        //////
    }

    {
        //////
        // begin variable-length header
        //////
        long ptr = 0;
        ssc_byte_t *vheader = sth_arena_alloc(arena, vheader_length);

        // set destination address type, address and port in variable-length header
        memcpy(vheader, s->dest.addr, s->dest.size);
        ptr += s->dest.size;

        // set padding length
        *((uint16_t*)&vheader[ptr]) = htons(padding_length);
        ptr += sizeof(uint16_t) + padding_length;

        if (with_initial_payload) {
            // write initial payload to variable-length header
            memcpy(&vheader[ptr], rdbuf->base, nread);
            assert((ptr + nread) == vheader_length);
        } else {
            // write initial payload to session's temporary buffer
            // and send it to remote server after handshake has been
            // completed
            s->initial_payload.len = nread;
            s->initial_payload.base = malloc(SSC_FULL_CHUNK_SIZE);
            assert(s->initial_payload.base != NULL);
            memcpy(s->initial_payload.base, rdbuf->base, nread);
        }

        ok = ssc_crypto_encrypt(&s->crypto,
                                &wrreq->buf.base[wrreq->buf.len], &encrypted_size,
                                &wrreq->buf.base[wrreq->buf.len + vheader_length], CRYPTO_TAG_SIZE,
                                vheader, vheader_length,
                                NULL, 0);
        assert(ok);
        assert(encrypted_size == vheader_length);

        wrreq->buf.len += vheader_length + CRYPTO_TAG_SIZE;
        sth_arena_pop(arena, vheader_length);
        //////
        // end variable-length header
        //////
    }

    uv_write((uv_write_t*)wrreq, (uv_stream_t*)client->dest, &wrreq->buf, 1, conn_write_cb);
    LOGI(SSC_ADDRSTR_FMT " --> " SSC_ADDRSTR_FMT ": wrote %ld bytes of ss handshake\n",
         SSC_ADDRSTR_ARGS(client), SSC_ADDRSTR_ARGS(&s->dest), wrreq->buf.len);

    uv_read_start((uv_stream_t*)&s->remote, buf_alloc_cb, remote_read_cb);
    return SSC_OK;
}

static void client_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *rdbuf) {
    ssc_conn_t *client = (ssc_conn_t*)stream;
    ssc_session_t *s = client->session;

    if (nread < 0) {
        if (nread != UV_EOF) {
            LOGE(SSC_ADDRSTR_FMT " read callback: %s\n", SSC_ADDRSTR_ARGS(client),
                 uv_strerror(nread));
        }
        ssc_conn_set_closing(loop, client->dest, conn_check_cb);
        uv_close((uv_handle_t*)client, conn_close_cb);
        goto ret;
    }

    switch (client->stage) {
        case CLIENT_STAGE_SOCKS5_METHOD_SELECTION:
            if (client_socks5_method_selection(stream, nread, rdbuf) == SSC_OK) {
                client->stage = CLIENT_STAGE_SOCKS5_REPLY;
            }
            break;

        case CLIENT_STAGE_SOCKS5_REPLY:
            if (client_socks5_prepare_reply(stream, nread, rdbuf) == SSC_OK) {
                client->stage = CLIENT_STAGE_SS_HANDSHAKE;
            }
            break;

        case CLIENT_STAGE_SS_HANDSHAKE:
            if (client_ss_handshake(stream, nread, rdbuf) == SSC_OK) {
                client->stage = CLIENT_STAGE_PROXY;
                client->dest->stage = REMOTE_STAGE_HANDSHAKE;
            }
            break;

        case CLIENT_STAGE_PROXY:
            {
                long ok, ptr;
                size_t encrypted_size;
                ssc_write_t *wrreq = sth_mempool_get(&wrreq_pool);
                wrreq->buf = (uv_buf_t){
                    .base = malloc(SSC_FULL_CHUNK_SIZE),
                    .len  = 0,
                };

                uint16_t nread_ne16 = htons(nread);
                ok = ssc_crypto_encrypt(&s->crypto,
                                        wrreq->buf.base, &encrypted_size,
                                        &wrreq->buf.base[sizeof(uint16_t)], CRYPTO_TAG_SIZE,
                                        &nread_ne16, sizeof(uint16_t),
                                        NULL, 0);
                assert(ok);
                assert(encrypted_size == sizeof(uint16_t));
                ptr = encrypted_size + CRYPTO_TAG_SIZE;
                wrreq->buf.len = ptr;

                ok = ssc_crypto_encrypt(&s->crypto,
                                        &wrreq->buf.base[ptr], &encrypted_size,
                                        &wrreq->buf.base[ptr + nread], CRYPTO_TAG_SIZE,
                                        rdbuf->base, nread,
                                        NULL, 0);
                assert(ok);
                assert(encrypted_size == nread);
                wrreq->buf.len += encrypted_size + CRYPTO_TAG_SIZE;

                uv_write((uv_write_t*)wrreq, (uv_stream_t*)client->dest, &wrreq->buf, 1, conn_write_cb);
                LOGI(SSC_ADDRSTR_FMT " --> " SSC_ADDRSTR_FMT ": wrote %ld bytes of data\n",
                     SSC_ADDRSTR_ARGS(client), SSC_ADDRSTR_ARGS(&s->dest), wrreq->buf.len);
            }
            break;
    };

ret:
    free(rdbuf->base);
}

static void remote_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *rdbuf) {
    ssc_write_t *wrreq;
    uint16_t payload_length = 0;
    long ok, encrypted_size, decrypted_size = 0, ptr = 0;

    ssc_conn_t *remote = (ssc_conn_t*)stream, *client = remote->dest;
    ssc_session_t *s = remote->session;

    if (nread < 0) {
        if (nread != UV_EOF)
            LOGE("(remote) read callback: %s\n", uv_strerror(nread));
        ssc_conn_set_closing(loop, remote->dest, conn_check_cb);
        uv_close((uv_handle_t*)remote, conn_close_cb);
        goto ret;
    }

    switch (remote->stage) {
        case REMOTE_STAGE_HANDSHAKE:
            {
                uint16_t header_size = (keysize == 32) ? 43 : 27;
                ssc_byte_t resp_header[43];

                // set decryption key
                ssc_crypto_dec_subkey_set(&s->crypto, key, rdbuf->base);
                ptr = keysize;

                ok = ssc_crypto_decrypt(&s->crypto,
                                        resp_header, &decrypted_size,
                                        &rdbuf->base[ptr], header_size,
                                        &rdbuf->base[ptr + header_size], CRYPTO_TAG_SIZE,
                                        NULL, 0);
                assert(ok);
                assert(decrypted_size == header_size);
                assert(resp_header[0] == 1);
                assert(memcmp(&resp_header[9], s->salt, keysize) == 0);

                ptr += header_size + CRYPTO_TAG_SIZE;
                payload_length = ntohs(*((uint16_t*) &resp_header[header_size - 2]));

                if (s->initial_payload.base) {
                    wrreq = sth_mempool_get(&wrreq_pool);
                    wrreq->buf = (uv_buf_t){
                        .base = malloc(SSC_FULL_CHUNK_SIZE),
                        .len  = 0
                    };

                    uint16_t n_ne16 = htons(s->initial_payload.len);
                    ok = ssc_crypto_encrypt(&s->crypto,
                                            wrreq->buf.base, &encrypted_size,
                                            &wrreq->buf.base[sizeof(uint16_t)], CRYPTO_TAG_SIZE,
                                            &n_ne16, sizeof(uint16_t),
                                            NULL, 0);
                    assert(ok);
                    assert(encrypted_size == sizeof(uint16_t));
                    ptr = encrypted_size + CRYPTO_TAG_SIZE;
                    wrreq->buf.len += ptr;

                    ok = ssc_crypto_encrypt(&s->crypto,
                                            &wrreq->buf.base[ptr], &encrypted_size,
                                            &wrreq->buf.base[ptr + nread], CRYPTO_TAG_SIZE,
                                            s->initial_payload.base, s->initial_payload.len,
                                            NULL, 0);
                    assert(ok);
                    assert(encrypted_size == nread);
                    wrreq->buf.len += encrypted_size + CRYPTO_TAG_SIZE;

                    uv_write((uv_write_t*)wrreq, (uv_stream_t*)remote, &wrreq->buf, 1, conn_write_cb);

                    free(s->initial_payload.base);
                    s->initial_payload.len = 0;

                    LOGI(SSC_ADDRSTR_FMT " --> " SSC_ADDRSTR_FMT ": wrote %ld bytes of first payload\n",
                         SSC_ADDRSTR_ARGS(client), SSC_ADDRSTR_ARGS(&s->dest), wrreq->buf.len);
                }

                if (payload_length > 0) {
                    wrreq = sth_mempool_get(&wrreq_pool);
                    wrreq->buf = (uv_buf_t){
                        .base = malloc(SSC_FULL_CHUNK_SIZE),
                        .len  = 0
                    };

                    ok = ssc_crypto_decrypt(&s->crypto,
                                            wrreq->buf.base, (long*) &wrreq->buf.len,
                                            &rdbuf->base[ptr], payload_length,
                                            &rdbuf->base[ptr + payload_length], CRYPTO_TAG_SIZE,
                                            NULL, 0);
                    assert(ok);
                    assert(payload_length == wrreq->buf.len);

                    uv_write((uv_write_t*)wrreq, (uv_stream_t*)client, &wrreq->buf, 1, conn_write_cb);
                    LOGI(SSC_ADDRSTR_FMT " <-- " SSC_ADDRSTR_FMT ": wrote %ld bytes of first payload\n",
                         SSC_ADDRSTR_ARGS(client), SSC_ADDRSTR_ARGS(&s->dest), wrreq->buf.len);
                }

                remote->stage = REMOTE_STAGE_PROXY;
            }
            break;

        case REMOTE_STAGE_PROXY:
            {
                char *base = rdbuf->base;
                assert(nread >= remote->pending_read);

                if (remote->pending_read > 0) {
                    memcpy(&s->tmpbuf.base[s->tmpbuf.len], base, remote->pending_read);
                    s->tmpbuf.len += remote->pending_read;

                    wrreq = sth_mempool_get(&wrreq_pool);
                    wrreq->buf = (uv_buf_t){
                        .base = malloc(SSC_FULL_CHUNK_SIZE),
                        .len  = 0
                    };

                    ok = ssc_crypto_decrypt(&s->crypto,
                                            wrreq->buf.base, (long*) &wrreq->buf.len,
                                            s->tmpbuf.base, s->tmpbuf.len - CRYPTO_TAG_SIZE,
                                            &s->tmpbuf.base[s->tmpbuf.len - CRYPTO_TAG_SIZE], CRYPTO_TAG_SIZE,
                                            NULL, 0);
                    assert(ok);
                    assert(wrreq->buf.len == (s->tmpbuf.len - CRYPTO_TAG_SIZE));

                    uv_write((uv_write_t*)wrreq, (uv_stream_t*)client, &wrreq->buf, 1, conn_write_cb);

                    nread -= remote->pending_read;
                    base += remote->pending_read;

                    remote->pending_read = 0;
                    s->tmpbuf.len = 0;
                }

                while (nread != 0) {
                    ok = ssc_crypto_decrypt(&s->crypto,
                                            &payload_length, &decrypted_size,
                                            base, sizeof(uint16_t),
                                            &base[sizeof(uint16_t)], CRYPTO_TAG_SIZE,
                                            NULL, 0);
                    if (!ok) {
                        LOGE(SSC_ADDRSTR_FMT " decrypt length chunk failed (nread = %ld)\n",
                             SSC_ADDRSTR_ARGS(remote->dest), nread);
                        uv_close((uv_handle_t*)remote, conn_close_cb);
                        uv_close((uv_handle_t*)remote->dest, conn_close_cb);
                        goto ret;
                    }
                    assert(ok);
                    assert(decrypted_size == sizeof(uint16_t));
                    nread -= sizeof(uint16_t) + CRYPTO_TAG_SIZE;
                    base += sizeof(uint16_t) + CRYPTO_TAG_SIZE;

                    payload_length = ntohs(payload_length);
                    if (payload_length + CRYPTO_TAG_SIZE > nread) {
                        remote->pending_read = (payload_length + CRYPTO_TAG_SIZE) - nread;
                        memcpy(s->tmpbuf.base, base, nread);
                        s->tmpbuf.len = nread;
                        goto ret;
                    }

                    wrreq = sth_mempool_get(&wrreq_pool);
                    wrreq->buf = (uv_buf_t){
                        .base = malloc(SSC_FULL_CHUNK_SIZE),
                        .len  = 0
                    };

                    ok = ssc_crypto_decrypt(&s->crypto,
                                            wrreq->buf.base, (long*) &wrreq->buf.len,
                                            base, payload_length,
                                            &base[payload_length], CRYPTO_TAG_SIZE,
                                            NULL, 0);
                    assert(ok);
                    assert(wrreq->buf.len == payload_length);

                    uv_write((uv_write_t*)wrreq, (uv_stream_t*)client, &wrreq->buf, 1, conn_write_cb);
                    LOGI(SSC_ADDRSTR_FMT " <-- " SSC_ADDRSTR_FMT ": wrote %ld bytes of data\n",
                         SSC_ADDRSTR_ARGS(remote->dest), SSC_ADDRSTR_ARGS(&s->dest), wrreq->buf.len);
                    nread -= payload_length + CRYPTO_TAG_SIZE;
                    base += payload_length + CRYPTO_TAG_SIZE;
                }
            }
            break;
    }

ret:
    free(rdbuf->base);
}

static void remote_connect_cb(uv_connect_t *req, int status) {
    ssc_conn_t *remote = (ssc_conn_t*)req->handle, *client = remote->dest;
    ssc_session_t *s = remote->session;

    ssc_write_t *wrreq = sth_mempool_get(&wrreq_pool);
    wrreq->buf = (uv_buf_t){
        .base = s->socksreply,
        .len = 10
    };

    if (status < 0) {
        switch (status) {
            case UV_ECONNREFUSED:
                s->socksreply[1] = SOCKS5_ConnectionRefused;
                break;
            default:
                s->socksreply[1] = SOCKS5_GeneralServerFailure;
        }
        LOGE("connection to remote failed: %s\n", uv_strerror(status));

        // write socks5 reply with error
        uv_write((uv_write_t*)wrreq, (uv_stream_t*)client, &wrreq->buf, 1, socks_reply_write_cb);
        ssc_conn_set_closing(loop, client, conn_check_cb);
        uv_close((uv_handle_t*)remote, conn_close_cb);
        return;
    }
    // write socks5 reply
    uv_write((uv_write_t*)wrreq, (uv_stream_t*)client, &wrreq->buf, 1, socks_reply_write_cb);

    s->tmpbuf.base = malloc(SSC_FULL_CHUNK_SIZE);

    // initialize session's crypto
    ssc_crypto_init(&s->crypto, cipher, keysize);

    // generate salt and set encryption subkey
    ssc_crypto_rand_bytes(s->salt, keysize);
    ssc_crypto_enc_subkey_set(&s->crypto, key, s->salt);

    // start reading again from client
    uv_read_start((uv_stream_t*)remote->dest, buf_alloc_cb, client_read_cb);
}

static void server_accept_cb(uv_stream_t *server, int status) {
    if (status <  0) {
        LOGE("new connection error: %s\n", uv_strerror(status));
        return;
    }

    ssc_sockaddr_in caddr;
    socklen_t caddr_len = sizeof(caddr);

    ssc_session_t *s = sth_mempool_get(&session_pool);
    {
        // Initialize session
        memset(s, 0, sizeof(*s));
        s->client.dest = &s->remote;
        s->remote.dest = &s->client;
    }

    ssc_conn_t *client = &s->client;
    uv_tcp_init(loop, (uv_tcp_t*)client);

    if (uv_accept(server, (uv_stream_t*)client) == 0) {
        uv_tcp_getpeername((uv_tcp_t*)client, (ssc_sockaddr*) &caddr, &caddr_len);

        uv_inet_ntop(caddr.sin_family, &caddr.sin_addr, client->addrstr, sizeof(client->addrstr));
        client->port = ntohs(caddr.sin_port);
        client->session = ssc_session_ref(s);

        uv_read_start((uv_stream_t*)client, buf_alloc_cb, client_read_cb);
        LOGI("new connection from " SSC_ADDRSTR_FMT "\n", SSC_ADDRSTR_ARGS(client));
    } else {
        uv_close((uv_handle_t*)client, (uv_close_cb)noop_cb);
        sth_mempool_put(&session_pool, s);
    }
}

static void sigint_cb(uv_signal_t *handle, int signum) {
    LOGI("SIGINT signal received. stopping the event loop...\n");
    uv_stop(loop);
}

int main(int argc, char *argv[]) {
    int err = 1;
    char *config_path;

    if (argc != 2) {
        LOGI("using default config file path " DEFAULT_CONFIG_PATH "\n");
        config_path = DEFAULT_CONFIG_PATH;
    } else {
        config_path = argv[1];
        LOGI("reading config file from %s\n", config_path);
    }

    sth_arena_config_t aconf = STH_ARENA_DEFAULT_CONFIG(.flags = STH_ARENA_FIXED);
    if ( !(arena = sth_arena_new(aconf)))
        goto ret;

    sth_mempool_init(&session_pool, arena, sizeof(ssc_session_t));
    sth_mempool_init(&wrreq_pool, arena, sizeof(ssc_write_t));

    ssc_config_t config;
    if ( (err = !ssc_config_read(arena, config_path, &config))) {
        LOGE("failed to read config file\n");
        goto ret_free_arena;
    }

    cipher = ssc_crypto_cipher_fetch(config.sf[CONFIG_METHOD], &keysize);
    sth_base64_decode(key, keysize, config.sf[CONFIG_PASSWORD]);

    loop = uv_default_loop();

    uv_signal_t sigint_handle;
    uv_signal_init(loop, &sigint_handle);
    uv_signal_start(&sigint_handle, sigint_cb, SIGINT);

    uv_ip4_addr(config.sf[CONFIG_LISTEN_ADDR], config.listen_port, &laddr);
    uv_ip4_addr(config.sf[CONFIG_REMOTE_ADDR], config.remote_port, &raddr);

    uv_tcp_t *server = sth_arena_alloc(arena, sizeof(*server));
    uv_tcp_init(loop, server);
    uv_tcp_bind(server, (ssc_sockaddr*) &laddr, 0);
    uv_listen((uv_stream_t*)server, SSC_LISTEN_BACKLOG, server_accept_cb);

    srandom(time(NULL) + (uintptr_t)arena + (uintptr_t)loop);
    LOGI("server listening on %s:%d\n", config.sf[CONFIG_LISTEN_ADDR], config.listen_port);
    uv_run(loop, UV_RUN_DEFAULT);

    LOGI("server shutdown...\n");
    err = 0;

ret_free_arena:
    sth_arena_destroy(arena);
ret:
    return err;
}
