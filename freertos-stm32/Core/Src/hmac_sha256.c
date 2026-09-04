#include "hmac_sha256.h"
#include "mbedtls/sha256.h"
#include <string.h>

#define SHA256_BLOCK_SIZE 64

/* mbedTLS's sha256.c calls this to wipe its internal context on
 * mbedtls_sha256_free(). Normally provided by platform_util.c, which we do
 * not vendor here (it pulls in mbedtls_ms_time(), a time-source dependency
 * this bare-metal build has no use for) -- a volatile byte-wise loop gives
 * the same "not optimised away" guarantee without that dependency. */
void mbedtls_platform_zeroize(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) *p++ = 0;
}

static void sha256_oneshot(const uint8_t *a, size_t a_len,
                            const uint8_t *b, size_t b_len,
                            uint8_t out[32])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0 /* SHA-256, not SHA-224 */);
    if (a && a_len) mbedtls_sha256_update(&ctx, a, a_len);
    if (b && b_len) mbedtls_sha256_update(&ctx, b, b_len);
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
}

void hmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t out[HMAC_SHA256_DIGEST_SIZE])
{
    uint8_t key_block[SHA256_BLOCK_SIZE];
    uint8_t ipad[SHA256_BLOCK_SIZE];
    uint8_t opad[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[32];

    memset(key_block, 0, sizeof(key_block));

    if (key_len > SHA256_BLOCK_SIZE) {
        /* Long keys are hashed down to 32 bytes first (RFC 2104). */
        sha256_oneshot(key, key_len, NULL, 0, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    /* inner = SHA256(ipad || msg) */
    sha256_oneshot(ipad, SHA256_BLOCK_SIZE, msg, msg_len, inner_hash);
    /* out = SHA256(opad || inner) */
    sha256_oneshot(opad, SHA256_BLOCK_SIZE, inner_hash, sizeof(inner_hash), out);

    /* Key material never needs to outlive this call. */
    volatile uint8_t *p;
    p = key_block; for (size_t i = 0; i < sizeof(key_block); i++) p[i] = 0;
    p = ipad;      for (size_t i = 0; i < sizeof(ipad);      i++) p[i] = 0;
    p = opad;      for (size_t i = 0; i < sizeof(opad);      i++) p[i] = 0;
    p = inner_hash;for (size_t i = 0; i < sizeof(inner_hash);i++) p[i] = 0;
}

int hmac_sha256_verify_constant_time(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}
