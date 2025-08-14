#ifndef _SSC_LOG_H_
#define _SSC_LOG_H_

#define LOGD(fmt, ...) \
    fprintf(stderr, "[DEBUG] %s:%d: " fmt, __FILE__, __LINE__, ## __VA_ARGS__)

#define LOGI(fmt, ...) \
    fprintf(stderr, "[INFO] " fmt, ## __VA_ARGS__)

#define LOGE(fmt, ...) \
    fprintf(stderr, "[ERROR] " fmt, ## __VA_ARGS__)

#endif // _SSC_LOG_H_
