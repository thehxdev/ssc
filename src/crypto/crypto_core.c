#include <blake3.h>

#define BLAKE3_KEY_DERIVATION_CONTEXT "shadowsocks 2022 session subkey"

typedef struct cipher_info {
    char *method;
    char *algo;
    unsigned char keysize;
} cipher_info_t;

static const cipher_info_t supported_ciphers[] = {
    { "2022-blake3-aes-128-gcm", "AES-128-GCM", 16 },
    { "2022-blake3-aes-256-gcm", "AES-256-GCM", 32 },
};

static const long n_supported_ciphers = \
    sizeof(supported_ciphers) / sizeof(*supported_ciphers);

static inline void iv_inc(unsigned char *iv) {
    uint32_t *high;
    uint64_t *low  = (uint64_t*) iv;
    *low += 1;
    if (*low == 0) {
        high = (uint32_t*) &iv[(sizeof(*low))];
        *high += 1;
    }
}

static inline int ssc_crypto_set_subkey(void *out,
                                        const void *key,
                                        const void *salt,
                                        size_t keysize)
{
    blake3_hasher hasher;
    memset(&hasher, 0, sizeof(hasher));
    blake3_hasher_init_derive_key(&hasher, BLAKE3_KEY_DERIVATION_CONTEXT);
    blake3_hasher_update(&hasher, key, keysize);
    blake3_hasher_update(&hasher, salt, keysize);
    blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);
    return 1;
}

int ssc_crypto_enc_subkey_set(ssc_crypto_t *self, const void *key, const void *salt) {
    return ssc_crypto_set_subkey(self->enc_subkey, key, salt, self->keysize);
}

int ssc_crypto_dec_subkey_set(ssc_crypto_t *self, const void *key, const void *salt) {
    return ssc_crypto_set_subkey(self->dec_subkey, key, salt, self->keysize);
}
