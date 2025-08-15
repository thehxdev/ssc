#ifndef _SSC_CRYPTO_H_
#define _SSC_CRYPTO_H_

#include <stddef.h>

#define IV_SIZE 12
#define TAG_SIZE 16
#define AES_MAX_KEY_SIZE 32
#define BLAKE3_KEY_SIZE  32

typedef void ssc_crypto_ctx;
typedef void ssc_crypto_cipher;

// NOTE: If the order of fields are changed, function 'ssc_crypto_deinit'
// probably needs modifications too.
typedef struct ssc_crypto {
    ssc_crypto_ctx *ctx;
    ssc_crypto_cipher *cipher;
    unsigned char keysize;
    unsigned char enc_subkey[BLAKE3_KEY_SIZE];
    unsigned char dec_subkey[BLAKE3_KEY_SIZE];
    unsigned char enc_iv[IV_SIZE];
    unsigned char dec_iv[IV_SIZE];
} ssc_crypto_t;

ssc_crypto_cipher *ssc_crypto_cipher_fetch(const char *method, unsigned char *keysize_out);

void ssc_crypto_cipher_free(ssc_crypto_cipher *cipher);

int ssc_crypto_init(ssc_crypto_t *self, ssc_crypto_cipher *cipher, unsigned char keysize);

int ssc_crypto_enc_subkey_set(ssc_crypto_t *self, const void *key, const void *salt);

int ssc_crypto_dec_subkey_set(ssc_crypto_t *self, const void *key, const void *salt);

int ssc_crypto_encrypt(ssc_crypto_t *self,
                       void *out, long *out_size,
                       void *tag_out, long tag_out_size,
                       const void *in, long in_size,
                       const void *auth_in, long auth_in_size);

int ssc_crypto_decrypt(ssc_crypto_t *self,
                       void *out, long *out_size,
                       const void *in, long in_size,
                       const void *tag, long tag_size,
                       const void *auth_in, long auth_in_size);

int ssc_crypto_deinit(ssc_crypto_t *self);

int ssc_crypto_rand_bytes(void *out, size_t n);

void ssc_crypto_hexdump(void *data, size_t n);

#endif // _SSC_CRYPTO_H_
