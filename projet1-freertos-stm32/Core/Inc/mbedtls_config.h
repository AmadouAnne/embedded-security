/* Minimal mbedTLS configuration for this project.
 * Only SHA-256 is needed (used to build our own HMAC-SHA256 construction
 * for UART challenge-response authentication) -- keeping the config this
 * small avoids pulling in the rest of mbedTLS's dependency graph (X.509,
 * TLS state machine, PSA crypto, ...) on a memory-constrained MCU. */
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_SMALLER

#endif /* MBEDTLS_CONFIG_H */
