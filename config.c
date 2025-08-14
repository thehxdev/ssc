#include <stdint.h>

// This is the config file for ssc Shadowsocks implementation. Users must
// compile this config file to a shared object file (.so on unix and .dll on
// windows)
//
// build command:
// $ cc -fPIC -shared -o config.so config.c

// socks5 listening address
const char listen_addr[] = "127.0.0.1";
const uint16_t listen_port = 1080;

// shadowsocks server address
const char remote_addr[] = "127.0.0.1";
const uint16_t remote_port = 2080;

// +------------------------------+---------------+
// |      supported method        |    key size   |
// +------------------------------+---------------+
// |   2022-blake3-aes-128-gcm    |    16-bytes   |
// |   2022-blake3-aes-256-gcm    |    32-bytes   |
// +------------------------------+---------------+
const char method[] = "2022-blake3-aes-256-gcm";

// password MUST be a base64 encoded value.
// generate a password with openssl (lookup KEY_SIZE from table above):
// $ openssl rand -base64 KEY_SIZE
//
// example for 2022-blake3-aes-256-gcm:
// $ openssl rand -base64 32
const char password[] = "BobTwUxsQsNeuOS2PW5CgYBsRPdQMxYpLDJsffr4KZc=";
