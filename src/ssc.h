#ifndef _SSC_SSC_H_
#define _SSC_SSC_H_

#include "crypto/crypto.h"
#include <netinet/in.h>

#define SSC_RDS_CAP     (2)
#define SSC_WRREQS_CAP  (8)

#define SSC_LENGTH_CHUNK_SIZE   (2 + TAG_SIZE)
#define SSC_PAYLOAD_CHUNK_SIZE  (STH_BASE_KB(64) + TAG_SIZE)
#define SSC_FULL_BUFFER_SIZE    (SSC_LENGTH_CHUNK_SIZE + SSC_PAYLOAD_CHUNK_SIZE)

enum {
    CLIENT_STAGE_SOCKS5_METHOD_SELECTION,
    CLIENT_STAGE_SOCKS5_REQUEST_REPLY,
    CLIENT_STAGE_HANDSHAKE,
    CLIENT_STAGE_PROXY,
};

enum {
    REMOTE_STAGE_HANDSHAKE,
    REMOTE_STAGE_PROXY,
};

typedef unsigned char ssc_byte_t;

typedef struct {
    ssc_byte_t *buf;
    size_t total, written;
} ssc_wrreq_t;

typedef struct {
    int fd, stage;

    // A ring buffer (queue) of write requests
    struct {
        ssc_wrreq_t items[SSC_WRREQS_CAP];
        size_t read, write, cap;
    } wrreqs;

    struct {
        // expected: How many bytes are expected to be read on the
        // next call to `read` or `recv`
        size_t read, expected;
        ssc_byte_t *buf;
    } rd;
} ssc_conn_t;

// typedef struct ssc_session {
//     ssc_conn_t client, remote;

//     ssc_crypto_t crypto;
//     ssc_byte_t salt[AES_MAX_KEY_SIZE];

//     char local_addr_str[INET6_ADDRSTRLEN + 7];
// } ssc_session_t;

#endif // _SSC_SSC_H_
