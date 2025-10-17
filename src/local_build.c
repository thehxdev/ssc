// #ifdef _MSC_VER
//     #pragma comment(lib, "Ws2_32.lib")
//     #pragma comment(lib, "user32.lib")
//     #pragma comment(lib, "advapi32.lib")
//     #pragma comment(lib, "iphlpapi.lib")
//     #pragma comment(lib, "shell32.lib")
//     #pragma comment(lib, "userenv.lib")
//     #pragma comment(lib, "psapi.lib")

//     #pragma comment(lib, "blake3.lib")
//     #pragma comment(lib, "uv.lib")
//     #pragma comment(lib, "libcrypto.lib")
// #endif

#include <uv.h>

#include "os/os.h"
#include "base/base.h"
#include "encoding/encoding.h"
#include "crypto/crypto.h"
#include "log.h"
#include "socks5.h"
#include "config.h"
#include "ss/ss.h"

#include "os/os.c"
#include "base/base.c"
#include "encoding/encoding.c"
#include "crypto/crypto.c"
#include "config.c"
#include "local.c"
