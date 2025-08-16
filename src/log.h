#ifndef _SSC_LOG_H_
#define _SSC_LOG_H_

// Logging system is based on shadowsocks-libev
// It's modified and only works for TTY.

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

#define LOGI(format, ...)                                           \
    do {                                                            \
        time_t now = time(NULL);                                    \
        char timestr[20];                                           \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));        \
        fprintf(stdout, "\e[01;32m%s INFO: \e[0m" format, timestr,  \
                ## __VA_ARGS__);                                    \
        fflush(stdout);                                             \
    } while (0)


#define LOGE(format, ...)                                           \
    do {                                                            \
        time_t now = time(NULL);                                    \
        char timestr[20];                                           \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));        \
        fprintf(stderr, "\e[01;35m%s ERROR: \e[0m" format, timestr, \
                ## __VA_ARGS__);                                    \
        fflush(stderr);                                             \
    } while (0)

#endif // _SSC_LOG_H_
