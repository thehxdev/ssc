#define STH_STRIP_PREFIX
#include "sth/sth.c"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <uv.h>

#include "crypto/crypto.h"
#include "log.h"
#include "socks5.h"
#include "config.h"
#include "ssc.h"

#include "cJSON/cJSON.c"
#include "crypto/crypto.c"
#include "config.c"
#include "socks5.c"
#include "ssc.c"
#include "local.c"
