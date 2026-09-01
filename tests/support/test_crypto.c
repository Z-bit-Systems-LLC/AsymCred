// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "test_crypto.h"

#include <string.h>

/* ---- SHA-256 (FIPS 180-4) ---------------------------------------------- */

static const uint32_t K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static uint32_t ror(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32U - n));
}

static void sha256_block(uint32_t h[8], const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, hh;

    for (size_t i = 0U; i < 16U; i++) {
        w[i] = ((uint32_t)block[i * 4U] << 24) |
               ((uint32_t)block[i * 4U + 1U] << 16) |
               ((uint32_t)block[i * 4U + 2U] << 8) |
               ((uint32_t)block[i * 4U + 3U]);
    }
    for (size_t i = 16U; i < 64U; i++) {
        uint32_t s0 = ror(w[i - 15U], 7) ^ ror(w[i - 15U], 18) ^ (w[i - 15U] >> 3);
        uint32_t s1 = ror(w[i - 2U], 17) ^ ror(w[i - 2U], 19) ^ (w[i - 2U] >> 10);
        w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (size_t i = 0U; i < 64U; i++) {
        uint32_t s1  = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
        uint32_t ch  = (e & f) ^ ((~e) & g);
        uint32_t t1  = hh + s1 + ch + K[i] + w[i];
        uint32_t s0  = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2  = s0 + maj;

        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void test_sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    uint32_t h[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    uint8_t  block[64];
    size_t   i;
    uint64_t bits = (uint64_t)len * 8U;

    for (i = 0U; i + 64U <= len; i += 64U) {
        sha256_block(h, &msg[i]);
    }

    /* Final block(s): remainder, 0x80, zero pad, 64-bit big-endian length. */
    size_t rem = len - i;
    (void)memset(block, 0, sizeof block);
    if (rem != 0U) {
        (void)memcpy(block, &msg[i], rem);
    }
    block[rem] = 0x80U;

    if (rem >= 56U) {
        sha256_block(h, block);
        (void)memset(block, 0, sizeof block);
    }

    for (size_t j = 0U; j < 8U; j++) {
        block[56U + j] = (uint8_t)(bits >> (56U - 8U * j));
    }
    sha256_block(h, block);

    for (size_t j = 0U; j < 8U; j++) {
        out[j * 4U]      = (uint8_t)(h[j] >> 24);
        out[j * 4U + 1U] = (uint8_t)(h[j] >> 16);
        out[j * 4U + 2U] = (uint8_t)(h[j] >> 8);
        out[j * 4U + 3U] = (uint8_t)(h[j]);
    }
}

/* ---- HAL bindings ------------------------------------------------------- */

static asymcred_status_t hal_sha256(void *user, const uint8_t *msg,
                                    size_t len, uint8_t out[32])
{
    (void)user;
    test_sha256(msg, len, out);
    return ASYMCRED_OK;
}

static asymcred_status_t hal_verify(void *user,
                                    const uint8_t pub[ASYMCRED_P256_PUBKEY_LEN],
                                    const uint8_t digest[ASYMCRED_SHA256_LEN],
                                    const uint8_t sig[ASYMCRED_P256_SIG_LEN])
{
    test_crypto_t *st = (test_crypto_t *)user;

    st->verify_called = true;
    (void)memcpy(st->last_pub, pub, ASYMCRED_P256_PUBKEY_LEN);
    (void)memcpy(st->last_digest, digest, ASYMCRED_SHA256_LEN);
    (void)memcpy(st->last_sig, sig, ASYMCRED_P256_SIG_LEN);

    return st->verify_result;
}

static asymcred_status_t hal_rand(void *user, uint8_t *out, size_t len)
{
    test_crypto_t *st = (test_crypto_t *)user;

    st->rand_called = true;
    (void)memset(out, st->rand_fill, len);

    return ASYMCRED_OK;
}

void test_crypto_init(asymcred_crypto_t *crypto, test_crypto_t *state)
{
    (void)memset(state, 0, sizeof(*state));
    state->verify_result = ASYMCRED_OK;
    state->rand_fill     = 0xA5U;

    crypto->sha256            = hal_sha256;
    crypto->ecdsa_p256_verify = hal_verify;
    crypto->rand_bytes        = hal_rand;
    crypto->user              = state;
}
