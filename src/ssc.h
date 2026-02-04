#ifndef _SSC_SSC_H_
#define _SSC_SSC_H_

#define SSC_LISTEN_BACKLOG  128

#define SSC_ADDRESS_STR_LEN     (256)
#define SSC_LENGTH_CHUNK_SIZE   (2 + CRYPTO_TAG_SIZE)
#define SSC_PAYLOAD_CHUNK_SIZE  (65536 + CRYPTO_TAG_SIZE)
#define SSC_FULL_CHUNK_SIZE     (SSC_LENGTH_CHUNK_SIZE + SSC_PAYLOAD_CHUNK_SIZE)

#define SSC_READ_BUFFER_SIZE    (65536)
#define SSC_MAX_PADDING_SIZE    (900)

#define SSC_CONN_STAGE_CLOSING (-1)

enum {
    SSC_OK,
    SSC_ERROR_SOCKS5_VERSION_MISMATCH,
    SSC_ERROR_SOCKS5_UNSUPPORTED_AUTH_METHOD,
    SSC_ERROR_SOCKS5_UNSUPPORTED_COMMAND,
    SSC_ERROR_SOCKS5_HANDSHAKE_FAILED,
};

enum {
    CLIENT_STAGE_SOCKS5_METHOD_SELECTION,
    CLIENT_STAGE_SOCKS5_REPLY,
    CLIENT_STAGE_SS_HANDSHAKE,
    CLIENT_STAGE_PROXY,
};

enum {
    REMOTE_STAGE_HANDSHAKE,
    REMOTE_STAGE_PROXY,
};

typedef unsigned char ssc_byte_t;

typedef struct sockaddr         ssc_sockaddr;
typedef struct sockaddr_in      ssc_sockaddr_in;
typedef struct sockaddr_in6     ssc_sockaddr_in6;
typedef struct sockaddr_storage ssc_sockaddr_storage;

typedef struct ssc_session_s ssc_session_t;

typedef struct ssc_fixed_header ssc_fixed_header_t;
STH_BASE_PACKED(struct ssc_fixed_header {
    uint8_t type;
    uint64_t timestamp;
    uint16_t length;
});

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} ssc_write_t;

#define SSC_ADDRSTR_FMT "%s:%d"
#define SSC_ADDRSTR_ARGS(conn)  (conn)->addrstr, (conn)->port

typedef struct ssc_conn_s {
    uv_tcp_t handle;

    // Check handle is initialized when connection enters
    // `closing` state and closes the connection when write
    // queue is empty.
    uv_check_t check_handle;

    struct ssc_conn_s *dest;
    ssc_session_t *session;

    size_t pending_read;
    int stage, port;

    char addrstr[INET6_ADDRSTRLEN];
} ssc_conn_t;

// A session is a container that holds shared data between client and remote
struct ssc_session_s {
    ssc_conn_t client, remote;
    uv_connect_t conreq;

    // session is reference counted
    int refcount;

    ssc_crypto_t crypto;
    ssc_byte_t salt[AES_MAX_KEY_SIZE];

    uv_buf_t initial_payload, tmpbuf;

    struct {
        size_t size;
        ssc_byte_t addr[SOCKS5_MAX_ADDR_SIZE];
        char addrstr[256];
        uint16_t port;
    } dest;

    ssc_byte_t socksreply[3 + SOCKS5_MAX_ADDR_SIZE];
};

#endif // _SSC_SSC_H_
