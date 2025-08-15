#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

ssc_static_assert(OPENSSL_VERSION_MAJOR == 3, check_openssl_version_3_x);

#define HEXDUMP_FP stderr

ssc_crypto_cipher *ssc_crypto_cipher_fetch(const char *method, unsigned char *keysize_out) {
    // supported ciphers length
    long scl = n_supported_ciphers;
    while (scl--)
        if (strcmp(supported_ciphers[scl].method, method) == 0)
            break;
    if (scl == -1)
        return NULL;
    *keysize_out = supported_ciphers[scl].keysize;
    return EVP_CIPHER_fetch(NULL, supported_ciphers[scl].algo, "provider=default");
}

void ssc_crypto_cipher_free(ssc_crypto_cipher *cipher) {
    EVP_CIPHER_free(cipher);
}

int ssc_crypto_init(ssc_crypto_t *self, ssc_crypto_cipher *cipher, unsigned char keysize) {
    self->ctx = EVP_CIPHER_CTX_new();
    if (!self->ctx)
        return 0;
    self->keysize = keysize;
    self->cipher = cipher;
    return 1;
}

int ssc_crypto_encrypt(ssc_crypto_t *self,
                       void *out, long *out_size,
                       void *tag_out, long tag_out_size,
                       const void *in, long in_size,
                       const void *auth_in, long auth_in_size)
{
    int tmp_size = 0, ok;
    EVP_CIPHER_CTX *ctx = self->ctx;

    ok = EVP_EncryptInit_ex(ctx, self->cipher, NULL, self->enc_subkey, self->enc_iv);
    if (!ok)
        goto ret;

    ok = EVP_EncryptUpdate(ctx, NULL, &tmp_size, auth_in, auth_in_size);
    if (!ok || tmp_size != auth_in_size)
        goto ret;

    ok = EVP_EncryptUpdate(ctx, out, &tmp_size, in, in_size);
    if (!ok)
        goto ret;
    *out_size = tmp_size;

    ok = EVP_EncryptFinal_ex(ctx, ((unsigned char*) out + tmp_size), &tmp_size);
    if (!ok)
        goto ret;
    *out_size += tmp_size;

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_out_size, tag_out);
    if (!ok)
        goto ret;

    iv_inc(self->enc_iv);
ret:
    return ok;
}

int ssc_crypto_decrypt(ssc_crypto_t *self,
                       void *out, long *out_size,
                       const void *in, long in_size,
                       const void *tag, long tag_size,
                       const void *auth_in, long auth_in_size)
{
    int tmp_size = 0, ok;
    EVP_CIPHER_CTX *ctx = self->ctx;

    ok = EVP_DecryptInit_ex(ctx, self->cipher, NULL, self->dec_subkey, self->dec_iv);
    if (!ok)
        goto ret;

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_size, (void*)tag);
    if (!ok)
        goto ret;

    ok = EVP_DecryptUpdate(ctx, NULL, &tmp_size, auth_in, auth_in_size);
    if (!ok)
        goto ret;

    ok = EVP_DecryptUpdate(ctx, out, &tmp_size, in, in_size);
    if (!ok)
        goto ret;
    *out_size = tmp_size;

    ok = EVP_DecryptFinal_ex(ctx, ((unsigned char*) out + tmp_size), &tmp_size);
    if (!ok)
        goto ret;
    *out_size += tmp_size;

    iv_inc(self->dec_iv);
ret:
    return ok;
}

int ssc_crypto_deinit(ssc_crypto_t *self) {
    if (!self->ctx)
        return 0;
    EVP_CIPHER_CTX_free(self->ctx);
    self->ctx = NULL;
    memset(self->enc_subkey, 0, (BLAKE3_OUT_LEN * 2) + (IV_SIZE * 2));
    return 1;
}

int ssc_crypto_rand_bytes(void *out, size_t n) {
    return RAND_bytes(out, n);
}

void ssc_crypto_hexdump(void *data, size_t n) {
    BIO_dump_fp(HEXDUMP_FP, data, n);
}
