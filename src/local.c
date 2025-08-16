#include <uv.h>

#define BUFFER_SIZE 0x10021

enum {
    CLIENT_STAGE_SOCKS5_METHOD_SELECTION,
    CLIENT_STAGE_SOCKS5_REQUEST_REPLY,
    CLIENT_STAGE_HANDSHAKE,
    CLIENT_STAGE_PROXY
};

enum {
    REMOTE_STAGE_HANDSHAKE,
    REMOTE_STAGE_PROXY
};

#undef assert
#define assert trap_assert

typedef struct ssc_write_req {
    uv_write_t req;
    uv_buf_t buf;
} ssc_write_req_t;

typedef struct ssc_session {
    uv_tcp_t client, remote;
    uv_connect_t conreq;
    ssc_crypto_t crypto;
    int client_stage, remote_stage;
    unsigned char salt[AES_MAX_KEY_SIZE];
    char socksreply[10];
    char addr_str[INET_ADDRSTRLEN + 7];
    long mustread;
    // temporary buffer
    long tmppos;
    char tmpbuf[BUFFER_SIZE];
} ssc_session_t;

// global memory - no malloc/free hell!
// just arena and pool allocators
static arena_t *gmem;
static ssc_mempool_t bufpool;
static ssc_mempool_t session_pool;
static ssc_mempool_t wrreq_pool;

static struct sockaddr_in lisaddr;
static struct sockaddr_in remaddr;

static ssc_crypto_cipher *cipher;
static unsigned char key[AES_MAX_KEY_SIZE];
static unsigned char keysize;

static uv_loop_t *loop;

static void dummy_func(void) {}

// allocate a buffer for libuv's "read" callbacks
static void buf_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    unused(handle); unused(suggested_size);
    buf->base = ssc_mempool_get(&bufpool);
    buf->len  = BUFFER_SIZE;
}

static void session_close_cb(uv_handle_t *handle) {
    ssc_session_t *s = handle->data;
    ssc_crypto_deinit(&s->crypto);
    LOGI("%s session closed\n", s->addr_str);
    ssc_mempool_put(&session_pool, s);
}

static void wrreq_put_cb(uv_write_t *req, int status) {
    unused(status);
    // if (status < 0)
    //     LOGE("%s write error!\n");
    ssc_mempool_put(&wrreq_pool, req);
}

static void wrreq_put_buf_cb(uv_write_t *req, int status) {
    unused(status);
    // if (status < 0)
    //     LOGE("write error!\n");
    ssc_write_req_t *wrreq = (ssc_write_req_t*) req;
    ssc_mempool_put(&bufpool, wrreq->buf.base);
    ssc_mempool_put(&wrreq_pool, wrreq);
}

static void socks_handshake_failed_cb(uv_write_t *req, int status) {
    unused(status);
    uv_close((uv_handle_t*) req->handle, session_close_cb);
    ssc_mempool_put(&wrreq_pool, req);
}

static void socks_reply_failed_cb(uv_write_t *req, int status) {
    unused(status);
    uv_close((uv_handle_t*) req->handle, session_close_cb);
    ssc_mempool_put(&wrreq_pool, req);
}

static void remote_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *rdbuf);
static void client_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *rdbuf);
static void remote_connect_cb(uv_connect_t *req, int status);

static void client_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *rdbuf) {
    ssc_write_req_t *wrreq;
    ssc_session_t *s = client->data;
    long ok, encrypted_size, ptr = 0;

    if (nread < 0 || nread == UV_EOF) {
        // TODO: read error must be handled seperately on each stage.
        if (nread != UV_EOF)
            LOGE("%s read callback: %s\n", s->addr_str, uv_strerror(nread));
        goto failed;
    }

    switch (s->client_stage) {
        case CLIENT_STAGE_SOCKS5_METHOD_SELECTION: {
            if (rdbuf->base[0] != SOCKS5_Version) {
                uv_close((uv_handle_t*) client, session_close_cb);
                goto ret;
            }
            wrreq = ssc_mempool_get(&wrreq_pool);
            wrreq->buf = (uv_buf_t){
                .base = s->socksreply,
                .len = 2
            };
            memcpy(wrreq->buf.base, (char[]){SOCKS5_Version, SOCKS5_NoAuth}, 2);
            int nmethods = rdbuf->base[1];
            char *methods_last = &rdbuf->base[nread - 1];
            while (nmethods--) {
                if (methods_last[nmethods] == SOCKS5_NoAuth)
                    break;
            }
            if (nmethods == -1) {
                wrreq->buf.base[1] = SOCKS5_NoAcceptableMethods;
                uv_write((uv_write_t*) wrreq, client, &wrreq->buf, 1, socks_handshake_failed_cb);
                goto ret;
            }
            uv_write((uv_write_t*) wrreq, client, &wrreq->buf, 1, wrreq_put_cb);
            s->client_stage++;
        }
        break;

        case CLIENT_STAGE_SOCKS5_REQUEST_REPLY: {
            memcpy(s->socksreply, (unsigned char[]){SOCKS5_Version, SOCKS5_Ok, SOCKS5_Reserved, SOCKS5_ATYPE_IPV4}, 4);
            memcpy(&s->socksreply[4], &lisaddr.sin_addr.s_addr, 4);
            memcpy(&s->socksreply[8], &lisaddr.sin_port, 2);

            if (rdbuf->base[1] != SOCKS5_Connect) {
                s->socksreply[1] = SOCKS5_CommandNotSupported;
                wrreq = ssc_mempool_get(&wrreq_pool);
                wrreq->buf = (uv_buf_t){
                    .base = s->socksreply,
                    .len = 10
                };

                uv_write((uv_write_t*) wrreq, client, &wrreq->buf, 1,
                         socks_handshake_failed_cb);
                uv_close((uv_handle_t*) client, session_close_cb);
                goto ret;
            }

            memcpy(s->tmpbuf, &rdbuf->base[3], nread - 3);
            s->tmppos = nread - 3;

            uv_tcp_connect(&s->conreq, &s->remote, (struct sockaddr*) &remaddr,
                           remote_connect_cb);
            uv_read_stop(client);

            s->client_stage++;
        }
        break;

        case CLIENT_STAGE_HANDSHAKE: {
            wrreq = ssc_mempool_get(&wrreq_pool);
            wrreq->buf = (uv_buf_t){
                .base = ssc_mempool_get(&bufpool),
                .len  = 0,
            };

            memcpy(wrreq->buf.base, s->salt, keysize);
            wrreq->buf.len += keysize;

            //////
            // begin fixed-length header
            //////
            unsigned char fheader[11];

            // set fixed-length header's type
            fheader[ptr++] = 0;

            // big endian timestamp
            // write timestamp to fixed-length header
            *((uint64_t*)&fheader[ptr]) = htobe64(time(NULL));
            ptr += sizeof(uint64_t);

            // set length field (variable-length header length) in fixed-length header
            long padding_length = (rand() % 900) + 1;
            long vheader_length = s->tmppos + sizeof(uint16_t) + padding_length + nread;
            assert(vheader_length <= UINT16_MAX);
            *((uint16_t*)&fheader[ptr]) = htobe16((uint16_t) vheader_length);

            // encrypt and write fixed-length header and it's tag to request buffer
            ok = ssc_crypto_encrypt(&s->crypto,
                                    &wrreq->buf.base[wrreq->buf.len], &encrypted_size,
                                    &wrreq->buf.base[wrreq->buf.len + sizeof(fheader)], TAG_SIZE,
                                    fheader, sizeof(fheader),
                                    NULL, 0);
            assert(ok);
            assert(encrypted_size == sizeof(fheader));
            wrreq->buf.len += sizeof(fheader) + TAG_SIZE;
            //////
            // end fixed-length header
            //////


            //////
            // begin variable-length header
            //////
            ptr = 0;
            unsigned char *vheader = arena_alloc(gmem, vheader_length);

            // set destination address type, address and port in variable-length header
            memcpy(&vheader[ptr], s->tmpbuf, s->tmppos);
            ptr += s->tmppos;
            s->tmppos = 0;

            // set padding length
            *((uint16_t*)&vheader[ptr]) = htobe16(padding_length);
            ptr += sizeof(uint16_t) + padding_length;

            // write initial payload
            memcpy(&vheader[ptr], rdbuf->base, nread);
            assert((ptr + nread) == vheader_length);

            ok = ssc_crypto_encrypt(&s->crypto,
                                    &wrreq->buf.base[wrreq->buf.len], &encrypted_size,
                                    &wrreq->buf.base[wrreq->buf.len + vheader_length], TAG_SIZE,
                                    vheader, vheader_length,
                                    NULL, 0);
            assert(ok);
            assert(encrypted_size == vheader_length);
            wrreq->buf.len += vheader_length + TAG_SIZE;
            //////
            // end variable-length header
            //////

            assert(wrreq->buf.len == (keysize + sizeof(fheader) + TAG_SIZE + vheader_length + TAG_SIZE));
            uv_write((uv_write_t*) wrreq, (uv_stream_t*) &s->remote, &wrreq->buf, 1, wrreq_put_buf_cb);
            LOGI("%s --> (remote): wrote %ld bytes of ss handshake\n", s->addr_str, wrreq->buf.len);

            arena_pop(gmem, vheader_length);

            s->remote_stage = REMOTE_STAGE_HANDSHAKE;
            uv_read_start((uv_stream_t*) &s->remote, buf_alloc_cb, remote_read_cb);

            s->client_stage++;
        }
        break;

        case CLIENT_STAGE_PROXY: {
            wrreq = ssc_mempool_get(&wrreq_pool);
            wrreq->buf = (uv_buf_t){
                .base = ssc_mempool_get(&bufpool),
                .len  = 0
            };

            uint16_t nread_be16 = htobe16(nread);
            ok = ssc_crypto_encrypt(&s->crypto,
                                    wrreq->buf.base, &encrypted_size,
                                    &wrreq->buf.base[sizeof(uint16_t)], TAG_SIZE,
                                    &nread_be16, sizeof(uint16_t),
                                    NULL, 0);
            assert(ok);
            assert(encrypted_size == sizeof(uint16_t));
            ptr = encrypted_size + TAG_SIZE;
            wrreq->buf.len = ptr;

            ok = ssc_crypto_encrypt(&s->crypto,
                                    &wrreq->buf.base[ptr], &encrypted_size,
                                    &wrreq->buf.base[ptr + nread], TAG_SIZE,
                                    rdbuf->base, nread,
                                    NULL, 0);
            assert(ok);
            assert(encrypted_size == nread);
            wrreq->buf.len += encrypted_size + TAG_SIZE;
            // ptr += encrypted_size + TAG_SIZE;

            uv_write((uv_write_t*) wrreq, (uv_stream_t*) &s->remote,
                     &wrreq->buf, 1, wrreq_put_buf_cb);
            LOGI("%s --> (remote): wrote %ld bytes of data\n", s->addr_str, wrreq->buf.len);
        }
        break;
    };

    goto ret;

failed:
    uv_close((uv_handle_t*) client, session_close_cb);
    uv_close((uv_handle_t*) &s->remote, (uv_close_cb) dummy_func);
ret:
    ssc_mempool_put(&bufpool, rdbuf->base);
}

static void remote_read_cb(uv_stream_t *remote, ssize_t nread, const uv_buf_t *rdbuf) {
    ssc_session_t *s = remote->data;
    if (nread < 0 || nread == UV_EOF) {
        if (nread != UV_EOF)
            LOGE("(remote): read callback: %s\n", uv_strerror(nread));
        goto failed;
    }

    if (nread == 0)
        goto ret;

    long ok, decrypted_size = 0;
    uint16_t payload_length = 0, ptr;
    ssc_write_req_t *wrreq;

    switch (s->remote_stage) {
        case REMOTE_STAGE_HANDSHAKE: {
            uint16_t header_size = (keysize == 32) ? 43 : 27;
            unsigned char resp_header[43];

            // set decryption key
            ssc_crypto_dec_subkey_set(&s->crypto, key, rdbuf->base);
            ptr = keysize;

            ok = ssc_crypto_decrypt(&s->crypto,
                                    resp_header, &decrypted_size,
                                    &rdbuf->base[ptr], header_size,
                                    &rdbuf->base[ptr + header_size], TAG_SIZE,
                                    NULL, 0);
            assert(ok);
            assert(decrypted_size == header_size);
            assert(resp_header[0] == 1);
            assert(memcmp(&resp_header[9], s->salt, keysize) == 0);

            ptr += header_size + TAG_SIZE;
            payload_length = ntohs(*((uint16_t*) &resp_header[header_size - 2]));

            wrreq = ssc_mempool_get(&wrreq_pool);
            wrreq->buf = (uv_buf_t){
                .base = ssc_mempool_get(&bufpool),
                .len  = 0
            };

            ok = ssc_crypto_decrypt(&s->crypto,
                                    wrreq->buf.base, (long*) &wrreq->buf.len,
                                    &rdbuf->base[ptr], payload_length,
                                    &rdbuf->base[ptr + payload_length], TAG_SIZE,
                                    NULL, 0);
            assert(ok);
            assert(payload_length == wrreq->buf.len);

            uv_write((uv_write_t*) wrreq, (uv_stream_t*) &s->client,
                     &wrreq->buf, 1, wrreq_put_buf_cb);
            LOGI("%s <-- (remote): wrote %ld bytes of first payload\n", s->addr_str, wrreq->buf.len);

            s->remote_stage++;
        }
        break;

        case REMOTE_STAGE_PROXY: {
            // if (nread <= 18) {
            //     LOGE("length chunk is not followed by a payload chunk (nread = %ld)\n", nread);
            //     goto ret;
            // }
            char *base = rdbuf->base;
            assert(nread >= s->mustread);
            if (s->mustread != 0) {
                memcpy(&s->tmpbuf[s->tmppos], base, s->mustread);

                s->tmppos += s->mustread;

                wrreq = ssc_mempool_get(&wrreq_pool);
                wrreq->buf = (uv_buf_t){
                    .base = ssc_mempool_get(&bufpool),
                    .len  = 0
                };

                ok = ssc_crypto_decrypt(&s->crypto,
                                        wrreq->buf.base, (long*) &wrreq->buf.len,
                                        s->tmpbuf, s->tmppos - TAG_SIZE,
                                        &s->tmpbuf[s->tmppos - TAG_SIZE], TAG_SIZE,
                                        NULL, 0);
                assert(ok);
                assert(wrreq->buf.len == (s->tmppos - TAG_SIZE));

                uv_write((uv_write_t*) wrreq, (uv_stream_t*) &s->client,
                         &wrreq->buf, 1, wrreq_put_buf_cb);

                nread -= s->mustread;
                base += s->mustread;

                s->mustread = 0;
                s->tmppos = 0;
            }
            while (nread != 0) {
                ok = ssc_crypto_decrypt(&s->crypto,
                                        &payload_length, &decrypted_size,
                                        base, sizeof(uint16_t),
                                        &base[sizeof(uint16_t)], TAG_SIZE,
                                        NULL, 0);
                if (!ok) {
                    LOGE("%s: decrypt length chunk failed (nread = %ld)\n", s->addr_str, nread);
                    goto failed;
                }
                assert(ok);
                assert(decrypted_size == sizeof(uint16_t));
                nread -= sizeof(uint16_t) + TAG_SIZE;
                base += sizeof(uint16_t) + TAG_SIZE;

                payload_length = ntohs(payload_length);
                if (payload_length + TAG_SIZE > nread) {
                    s->mustread = (payload_length + TAG_SIZE) - nread;
                    memcpy(s->tmpbuf, base, nread);
                    s->tmppos = nread;
                    goto ret;
                }
                // assert(nread >= (payload_length + TAG_SIZE));

                wrreq = ssc_mempool_get(&wrreq_pool);
                wrreq->buf = (uv_buf_t){
                    .base = ssc_mempool_get(&bufpool),
                    .len  = 0
                };

                ok = ssc_crypto_decrypt(&s->crypto,
                                        wrreq->buf.base, (long*) &wrreq->buf.len,
                                        base, payload_length,
                                        &base[payload_length], TAG_SIZE,
                                        NULL, 0);
                assert(ok);
                assert(wrreq->buf.len == payload_length);

                uv_write((uv_write_t*) wrreq, (uv_stream_t*) &s->client,
                         &wrreq->buf, 1, wrreq_put_buf_cb);
                LOGI("%s <-- (remote): wrote %ld bytes of data\n", s->addr_str, wrreq->buf.len);
                nread -= payload_length + TAG_SIZE;
                base += payload_length + TAG_SIZE;
            }
        }
        break;
    }

    goto ret;

failed:
    uv_close((uv_handle_t*) remote, session_close_cb);
    uv_close((uv_handle_t*) &s->client, (uv_close_cb) dummy_func);
ret:
    ssc_mempool_put(&bufpool, rdbuf->base);
}

// TODO: must add a timer to catch connection timeouts to remote server
static void remote_connect_cb(uv_connect_t *req, int status) {
    uv_stream_t *remote = req->handle;
    ssc_session_t *s = remote->data;

    ssc_write_req_t *wrreq = ssc_mempool_get(&wrreq_pool);
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
        uv_write((uv_write_t*) wrreq, (uv_stream_t*) &s->client,
                 &wrreq->buf, 1, socks_reply_failed_cb);

        uv_close((uv_handle_t*) remote, (uv_close_cb) dummy_func);
        return;
    }
    // write socks5 reply
    uv_write((uv_write_t*) wrreq, (uv_stream_t*) &s->client,
             &wrreq->buf, 1, wrreq_put_cb);

    // initialize session's crypto
    ssc_crypto_init(&s->crypto, cipher, keysize);

    // generate salt and set encryption subkey
    ssc_crypto_rand_bytes(s->salt, keysize);
    ssc_crypto_enc_subkey_set(&s->crypto, key, s->salt);

    // start reading again from client
    uv_read_start((uv_stream_t*) &s->client, buf_alloc_cb, client_read_cb);
}

static void server_accept_cb(uv_stream_t *socks_server, int status) {
    (void)status;

    struct sockaddr_in caddr;
    int caddr_len = sizeof(caddr);
    char addrstr[INET_ADDRSTRLEN];

    ssc_session_t *s = ssc_mempool_get(&session_pool);
    memset(s, 0, sizeof(*s));

    s->client.data = s->remote.data = s;
    uv_tcp_init(loop, &s->client);
    uv_tcp_init(loop, &s->remote);

    uv_accept(socks_server, (uv_stream_t*) &s->client);
    uv_tcp_getpeername(&s->client, (struct sockaddr*) &caddr, &caddr_len);

    uv_inet_ntop(caddr.sin_family, &caddr.sin_addr, addrstr, (socklen_t)caddr_len);
    snprintf(s->addr_str, sizeof(s->addr_str)-1, "%s:%d", addrstr, ntohs(caddr.sin_port));
    LOGI("new connection from %s\n", s->addr_str);

    uv_read_start((uv_stream_t*) &s->client, buf_alloc_cb, client_read_cb);
}

static void sigint_cb(uv_signal_t *handle, int signum) {
    unused(signum); unused(handle);
    uv_stop(loop);
}

int main(int argc, char *argv[]) {
    int err = 1;
    char *config_path;

    if (argc != 2)
        config_path = "./config.so";
    else
        config_path = argv[1];

    arena_config_t aconf = ARENA_DEFAULT_CONFIG;
    aconf.flags   = ARENA_FIXED;
    aconf.reserve = ARENA_MB(128ULL);
    aconf.commit  = ARENA_MB(16ULL);
    if ( !(gmem = arena_new(&aconf)))
        goto ret;

    ssc_mempool_init(&bufpool, gmem, BUFFER_SIZE);
    ssc_mempool_init(&session_pool, gmem, sizeof(ssc_session_t));
    ssc_mempool_init(&wrreq_pool, gmem, sizeof(ssc_write_req_t));

    struct ssc_config config;
    if ( (err = !ssc_config_readall(gmem, config_path, &config)))
        goto ret_free_gmem;

    cipher = ssc_crypto_cipher_fetch(config.sf[CONFIG_METHOD], &keysize);
    base64_decode(key, keysize, config.sf[CONFIG_PASSWORD]);

    loop = uv_default_loop();

    uv_signal_t sigint_handle;
    uv_signal_init(loop, &sigint_handle);
    uv_signal_start(&sigint_handle, sigint_cb, SIGINT);

    uv_ip4_addr(config.sf[CONFIG_LISTEN_ADDR], config.listen_port, &lisaddr);
    uv_ip4_addr(config.sf[CONFIG_REMOTE_ADDR], config.remote_port, &remaddr);

    uv_tcp_t *socks_server = arena_alloc(gmem, sizeof(*socks_server));
    uv_tcp_init(loop, socks_server);
    uv_tcp_bind(socks_server, (struct sockaddr*) &lisaddr, 0);
    uv_listen((uv_stream_t*)socks_server, 128, server_accept_cb);

    srand(time(NULL));
    LOGI("server listening on %s:%d\n", config.sf[CONFIG_LISTEN_ADDR], config.listen_port);
    uv_run(loop, UV_RUN_DEFAULT);

    LOGI("server shutdown...\n");
    err = 0;

ret_free_gmem:
    arena_destroy(gmem);
ret:
    return err;
}
