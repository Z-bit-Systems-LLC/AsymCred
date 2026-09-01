// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef ASYMCRED_CRYPTO_H
#define ASYMCRED_CRYPTO_H

#include "asymcred/asymcred_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* asymcred_crypto — abstract cryptographic primitive HAL.
 *
 * PKOC reader-side verification reduces to two primitives: SHA-256 over
 * the transaction identifier, and an ECDSA P-256 signature verification
 * of the resulting digest against the public key the card presented
 * (PKOC 1.1 flow step 6/7 — NIST FIPS 186-5 section 6, raw R||S, never
 * ASN.1). A third, a CSPRNG, supplies the transaction identifier.
 *
 * As in OSDP-Embedded, the library never vendors a crypto implementation.
 * The consumer fills the vtable from whatever suits the deployment:
 *
 *   - Bare-metal MCU: a hardware PKA / ECC peripheral (STM32 PKA,
 *     nRF CryptoCell, ESP32 ECC accelerator), plus its TRNG.
 *   - Software-only MCU: micro-ecc (uECC_verify) or tinycrypt.
 *   - Linux/POSIX: mbedTLS, OpenSSL, BearSSL.
 *
 * Constant-time and side-channel hardening are the implementer's
 * responsibility. Note that signature *verification* operates only on
 * public values, so it is far less side-channel sensitive than the
 * card-side signing operation.
 *
 * The transaction identifier is the sole defence against replay of a
 * captured card response. `rand_bytes` MUST be a cryptographically
 * secure generator — a counter, a timestamp, or a PRNG seeded from a
 * fixed value defeats the protocol. */

#define ASYMCRED_SHA256_LEN      32U
#define ASYMCRED_P256_PUBKEY_LEN 65U /* 0x04 || X(32) || Y(32), SEC 1 */
#define ASYMCRED_P256_SIG_LEN    64U /* R(32) || S(32), not ASN.1     */

typedef struct asymcred_crypto {
    /* Hash `len` bytes at `msg` into `out`. Required whenever signature
     * verification is enabled. */
    asymcred_status_t (*sha256)(
        void          *user,
        const uint8_t *msg,
        size_t         len,
        uint8_t        out[ASYMCRED_SHA256_LEN]);

    /* Verify a P-256 signature over an already-computed digest.
     *
     * `pub` is the 65-byte uncompressed point exactly as the card sent
     * it (leading 0x04). `sig` is the raw 64-byte R||S concatenation.
     *
     * Return ASYMCRED_OK only when the signature is valid. Return
     * ASYMCRED_ERR_BAD_SIGNATURE when the maths completed and the
     * signature is wrong, or when `pub` is not a valid curve point.
     * Reserve the other status codes for caller-violation conditions.
     *
     * Required whenever signature verification is enabled. */
    asymcred_status_t (*ecdsa_p256_verify)(
        void          *user,
        const uint8_t  pub   [ASYMCRED_P256_PUBKEY_LEN],
        const uint8_t  digest[ASYMCRED_SHA256_LEN],
        const uint8_t  sig   [ASYMCRED_P256_SIG_LEN]);

    /* Fill `out` with `len` cryptographically-random bytes. Required
     * unless every transaction identifier is supplied by the caller
     * through asymcred_pkoc_begin_with_transaction_id(). */
    asymcred_status_t (*rand_bytes)(void *user, uint8_t *out, size_t len);

    /* Opaque pointer threaded back into all callbacks. */
    void *user;
} asymcred_crypto_t;

#ifdef __cplusplus
}
#endif

#endif /* ASYMCRED_CRYPTO_H */
