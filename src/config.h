#ifndef _SSC_H_
#define _SSC_H_

enum {
    CONFIG_LISTEN_ADDR,
    CONFIG_REMOTE_ADDR,
    CONFIG_METHOD,
    CONFIG_PASSWORD,

    _CONFIG_SF_COUNT,
};

typedef struct {
    // string fields
    char *sf[_CONFIG_SF_COUNT];
    uint16_t listen_port;
    uint16_t remote_port;
} ssc_config_t;

int ssc_config_read(sth_arena_t *arena, const char *path, ssc_config_t *config);

#endif // _SSC_H_
