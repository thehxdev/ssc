#include <string.h>
#include "config.h"
#include "sth/sth.h"
#include "cJSON/cJSON.h"

static const char *sf_map[_CONFIG_SF_COUNT] = {
    [CONFIG_LISTEN_ADDR] = "listen_addr",
    [CONFIG_REMOTE_ADDR] = "remote_addr",
    [CONFIG_METHOD]      = "method",
    [CONFIG_PASSWORD]    = "password",
};

int ssc_config_read(sth_arena_t *arena, const char *path, ssc_config_t *config) {
    cJSON *j;
    int i, ok = 1;

    size_t config_size = 0;
    char *config_string = sth_io_file_read_all(path, &config_size);
    if (!config_string) {
        ok = 0;
        goto ret;
    }

    cJSON *config_json = cJSON_ParseWithLength(config_string, config_size);
    if (!config_json) {
        ok = 0;
        goto ret_free_config_string;
    }

    for (int i = 0; i < _CONFIG_SF_COUNT; i++) {
        const char *s = cJSON_GetObjectItem(config_json, sf_map[i])->valuestring;
        config->sf[i] = sth_arena_strndup(arena, s, strlen(s));
    }

    config->listen_port = cJSON_GetObjectItem(config_json, "listen_port")->valuedouble;
    config->remote_port = cJSON_GetObjectItem(config_json, "remote_port")->valuedouble;
    cJSON_free(config_json);

ret_free_config_string:
    STH_BASE_FREE(config_string);
ret:
    return ok;
}
