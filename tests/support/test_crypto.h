// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef ASYMCRED_TEST_CRYPTO_H
#define ASYMCRED_TEST_CRYPTO_H

#include "asymcred/asymcred_crypto.h"

/* Test-only crypto binding.
 *
 * The library never vendors crypto (see CLAUDE.md), so the tests supply
 * their own. SHA-256 here is a real implementation - it is small, and a
 * real one lets a test assert the exact digest the state machine hands
 * to verification, which is how we pin down *what* gets signed.
 *
 * ECDSA verification is a scriptable stub rather than a real P-256: it
 * records the arguments it was called with and returns a verdict the
 * test chooses. That covers the state machine's contract (is verify
 * called, with which bytes, and what happens when it fails). It does
 * NOT prove our verification maths, because there is none to prove -
 * the real implementation is the consumer's. Binding micro-ecc for an
 * end-to-end check against the spec vector is the next step; the vector
 * itself is already known good (verified with openssl - see
 * tests/test_pkoc.c). */

void test_sha256(const uint8_t *msg, size_t len, uint8_t out[32]);

typedef struct test_crypto {
    /* Verdict test_ecdsa_verify returns. */
    asymcred_status_t verify_result;

    /* Arguments captured from the most recent verify call. */
    bool    verify_called;
    uint8_t last_pub[ASYMCRED_P256_PUBKEY_LEN];
    uint8_t last_digest[ASYMCRED_SHA256_LEN];
    uint8_t last_sig[ASYMCRED_P256_SIG_LEN];

    /* Bytes rand_bytes hands out, and whether it was asked. */
    uint8_t rand_fill;
    bool    rand_called;
} test_crypto_t;

/* Fill `crypto` with callbacks bound to `state` (zeroed, verdict OK). */
void test_crypto_init(asymcred_crypto_t *crypto, test_crypto_t *state);

#endif /* ASYMCRED_TEST_CRYPTO_H */
