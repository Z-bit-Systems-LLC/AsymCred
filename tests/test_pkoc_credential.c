// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "asymcred/asymcred_pkoc.h"
#include "support/test_crypto.h"
#include "unity.h"

#include <string.h>

/* The public key from the PKOC 1.1 spec's worked example. */
static const uint8_t SPEC_PUBKEY[65] = {
    0x04U,
    0x0EU, 0xC5U, 0xD8U, 0x7DU, 0xC3U, 0x9DU, 0x14U, 0xA2U,
    0xC5U, 0x48U, 0x06U, 0x86U, 0xDAU, 0x86U, 0x0CU, 0x82U,
    0xB1U, 0x6BU, 0xE0U, 0xB6U, 0x90U, 0x3BU, 0x52U, 0x5FU,
    0x84U, 0x84U, 0x8BU, 0x79U, 0xFDU, 0x46U, 0x3EU, 0x32U,
    0xBBU, 0xDAU, 0x1FU, 0x02U, 0x52U, 0xC3U, 0x35U, 0x03U,
    0xC5U, 0x28U, 0x70U, 0x35U, 0xE6U, 0xEAU, 0xC5U, 0x5DU,
    0x13U, 0x8DU, 0x06U, 0x50U, 0xDCU, 0xFBU, 0x52U, 0x81U,
    0xD5U, 0x9AU, 0x9CU, 0xF4U, 0x12U, 0x4DU, 0x28U, 0x31U
};

void setUp(void) { }
void tearDown(void) { }

static void test_256bit_is_the_x_component(void)
{
    uint8_t out[32];
    size_t  written = 0U;
    size_t  bits    = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_credential(SPEC_PUBKEY, ASYMCRED_PKOC_CRED_256BIT,
                                 out, sizeof out, &written, &bits));

    TEST_ASSERT_EQUAL_size_t(32U, written);
    TEST_ASSERT_EQUAL_size_t(256U, bits);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(&SPEC_PUBKEY[1], out, 32);
}

static void test_64bit_is_the_low_eight_bytes_of_x(void)
{
    static const uint8_t expect[8] = {
        0x84U, 0x84U, 0x8BU, 0x79U, 0xFDU, 0x46U, 0x3EU, 0x32U
    };

    uint8_t out[8];
    size_t  written = 0U;
    size_t  bits    = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_credential(SPEC_PUBKEY, ASYMCRED_PKOC_CRED_64BIT,
                                 out, sizeof out, &written, &bits));

    TEST_ASSERT_EQUAL_size_t(8U, written);
    TEST_ASSERT_EQUAL_size_t(64U, bits);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, out, 8);
}

static void test_75bit_keeps_three_bits_of_the_ninth_byte(void)
{
    /* X ends ... 52 5F 84 84 8B 79 FD 46 3E 32.
     * The low 72 bits are the last nine bytes; the remaining three come
     * from 0x52 masked to 0x02. The five bits above that are dropped. */
    static const uint8_t expect[10] = {
        0x02U, 0x5FU, 0x84U, 0x84U, 0x8BU, 0x79U, 0xFDU, 0x46U,
        0x3EU, 0x32U
    };

    uint8_t out[10];
    size_t  written = 0U;
    size_t  bits    = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_credential(SPEC_PUBKEY, ASYMCRED_PKOC_CRED_75BIT,
                                 out, sizeof out, &written, &bits));

    TEST_ASSERT_EQUAL_size_t(10U, written);
    TEST_ASSERT_EQUAL_size_t(75U, bits);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, out, 10);

    /* The five unused high bits must be clear, or an osdp_RAW payload
     * built from this would carry junk above the declared bit count. */
    TEST_ASSERT_EQUAL_HEX8(0U, out[0] & 0xF8U);
}

static void test_truncated_forms_are_suffixes_of_the_full_credential(void)
{
    uint8_t full[32], narrow[8];
    size_t  w = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_credential(SPEC_PUBKEY, ASYMCRED_PKOC_CRED_256BIT,
                                 full, sizeof full, &w, NULL));
    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_credential(SPEC_PUBKEY, ASYMCRED_PKOC_CRED_64BIT,
                                 narrow, sizeof narrow, &w, NULL));

    TEST_ASSERT_EQUAL_UINT8_ARRAY(&full[24], narrow, 8);
}

static void test_rejects_undersized_buffer(void)
{
    uint8_t out[9]; /* 75-bit needs 10 */
    size_t  written = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BUFFER_TOO_SMALL,
        asymcred_pkoc_credential(SPEC_PUBKEY, ASYMCRED_PKOC_CRED_75BIT,
                                 out, sizeof out, &written, NULL));
}

static void test_rejects_non_uncompressed_key(void)
{
    uint8_t key[65];
    uint8_t out[32];
    size_t  written = 0U;

    (void)memcpy(key, SPEC_PUBKEY, sizeof key);
    key[0] = 0x02U;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_INVALID_ARG,
        asymcred_pkoc_credential(key, ASYMCRED_PKOC_CRED_256BIT,
                                 out, sizeof out, &written, NULL));
}

static void test_bit_len_is_optional(void)
{
    uint8_t out[8];
    size_t  written = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_credential(SPEC_PUBKEY, ASYMCRED_PKOC_CRED_64BIT,
                                 out, sizeof out, &written, NULL));
    TEST_ASSERT_EQUAL_size_t(8U, written);
}

/* Known-answer tests for the test harness's own SHA-256. If these fail,
 * every digest assertion elsewhere is meaningless. */
static void test_sha256_known_answers(void)
{
    static const uint8_t empty[32] = {
        0xE3U, 0xB0U, 0xC4U, 0x42U, 0x98U, 0xFCU, 0x1CU, 0x14U,
        0x9AU, 0xFBU, 0xF4U, 0xC8U, 0x99U, 0x6FU, 0xB9U, 0x24U,
        0x27U, 0xAEU, 0x41U, 0xE4U, 0x64U, 0x9BU, 0x93U, 0x4CU,
        0xA4U, 0x95U, 0x99U, 0x1BU, 0x78U, 0x52U, 0xB8U, 0x55U
    };
    static const uint8_t abc[32] = {
        0xBAU, 0x78U, 0x16U, 0xBFU, 0x8FU, 0x01U, 0xCFU, 0xEAU,
        0x41U, 0x41U, 0x40U, 0xDEU, 0x5DU, 0xAEU, 0x22U, 0x23U,
        0xB0U, 0x03U, 0x61U, 0xA3U, 0x96U, 0x17U, 0x7AU, 0x9CU,
        0xB4U, 0x10U, 0xFFU, 0x61U, 0xF2U, 0x00U, 0x15U, 0xADU
    };

    uint8_t out[32];

    test_sha256((const uint8_t *)"", 0U, out);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(empty, out, 32);

    test_sha256((const uint8_t *)"abc", 3U, out);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(abc, out, 32);
}

/* A message that straddles the 55/56-byte padding boundary, where a
 * SHA-256 implementation either emits the extra block or corrupts. */
static void test_sha256_padding_boundary(void)
{
    static const uint8_t expect[32] = {
        0xB3U, 0x54U, 0x39U, 0xA4U, 0xACU, 0x6FU, 0x09U, 0x48U,
        0xB6U, 0xD6U, 0xF9U, 0xE3U, 0xC6U, 0xAFU, 0x0FU, 0x5FU,
        0x59U, 0x0CU, 0xE2U, 0x0FU, 0x1BU, 0xDEU, 0x70U, 0x90U,
        0xEFU, 0x79U, 0x70U, 0x68U, 0x6EU, 0xC6U, 0x73U, 0x8AU
    };

    /* 56 'a' characters. */
    uint8_t msg[56];
    uint8_t out[32];

    (void)memset(msg, 'a', sizeof msg);
    test_sha256(msg, sizeof msg, out);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, out, 32);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_256bit_is_the_x_component);
    RUN_TEST(test_64bit_is_the_low_eight_bytes_of_x);
    RUN_TEST(test_75bit_keeps_three_bits_of_the_ninth_byte);
    RUN_TEST(test_truncated_forms_are_suffixes_of_the_full_credential);
    RUN_TEST(test_rejects_undersized_buffer);
    RUN_TEST(test_rejects_non_uncompressed_key);
    RUN_TEST(test_bit_len_is_optional);

    RUN_TEST(test_sha256_known_answers);
    RUN_TEST(test_sha256_padding_boundary);

    return UNITY_END();
}
