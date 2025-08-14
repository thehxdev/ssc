#ifndef _SSC_H_
#define _SSC_H_

enum {
    CONFIG_LISTEN_ADDR,
    CONFIG_REMOTE_ADDR,
    CONFIG_METHOD,
    CONFIG_PASSWORD,

    _CONFIG_SF_COUNT,
};

struct ssc_config {
    // string fields
    char *sf[_CONFIG_SF_COUNT];
    uint16_t listen_port;
    uint16_t remote_port;
};

typedef struct ssc_manager {
    ssc_crypto_cipher *cipher;
    struct ssc_config config;
    // struct sockaddr remaddr, lisaddr;
    unsigned char key[AES_MAX_KEY_SIZE+1];
    unsigned char keysize;
} ssc_manager_t;

int ssc_config_readall(arena_t *arena, const char *dlpath, struct ssc_config *config);

#endif // _SSC_H_
