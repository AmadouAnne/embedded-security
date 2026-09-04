#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define HMAC_SHA256_DIGEST_SIZE 32

/* RFC 2104 HMAC construction built on top of mbedTLS's SHA-256 primitive
 * (mbedtls_sha256_starts/update/finish). Key material is zeroized from the
 * padded buffers as soon as the block digests have been produced. */
void hmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t out[HMAC_SHA256_DIGEST_SIZE]);

/* Constant-time comparison -- avoids leaking how many leading bytes of the
 * response matched via a timing side channel when verifying a MAC. */
int hmac_sha256_verify_constant_time(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* HMAC_SHA256_H */
