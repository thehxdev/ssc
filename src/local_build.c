#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#define STH_STRIP_PREFIX
#include "sth/sth.h"
#include "cJSON/cJSON.h"
#include "crypto/crypto.h"
#include "log.h"
#include "socks5.h"
#include "config.h"
#include "ss.h"
#include "ssc.h"

#include "sth/sth.c"
#include "cJSON/cJSON.c"
#include "crypto/crypto.c"
#include "config.c"
#include "local.c"
