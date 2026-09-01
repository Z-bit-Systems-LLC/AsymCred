// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "asymcred/asymcred_apdu.h"
#include "unity.h"

void setUp(void) { }
void tearDown(void) { }

static void test_builds_case4_short_apdu(void)
{
    static const uint8_t aid[8] = {
        0xA0U, 0x00U, 0x00U, 0x08U, 0x98U, 0x00U, 0x00U, 0x01U
    };
    static const uint8_t expect[14] = {
        0x00U, 0xA4U, 0x04U, 0x00U, 0x08U,
        0xA0U, 0x00U, 0x00U, 0x08U, 0x98U, 0x00U, 0x00U, 0x01U,
        0x00U
    };

    uint8_t buf[32];
    size_t  written = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_apdu_build(0x00U, 0xA4U, 0x04U, 0x00U,
                            aid, sizeof aid, 0x00U,
                            buf, sizeof buf, &written));

    TEST_ASSERT_EQUAL_size_t(sizeof expect, written);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, buf, written);
}

static void test_build_rejects_empty_body(void)
{
    uint8_t buf[16];
    size_t  written = 0U;
    uint8_t data    = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_INVALID_ARG,
        asymcred_apdu_build(0x00U, 0xA4U, 0x04U, 0x00U,
                            &data, 0U, 0x00U, buf, sizeof buf, &written));
}

static void test_build_respects_capacity(void)
{
    uint8_t data[8] = { 0 };
    uint8_t buf[8];
    size_t  written = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BUFFER_TOO_SMALL,
        asymcred_apdu_build(0x00U, 0xA4U, 0x04U, 0x00U,
                            data, sizeof data, 0x00U,
                            buf, sizeof buf, &written));
}

static void test_splits_body_and_status_word(void)
{
    static const uint8_t rapdu[6] = {
        0x5CU, 0x02U, 0x01U, 0x00U, 0x90U, 0x00U
    };

    const uint8_t *body     = NULL;
    size_t         body_len = 0U;
    uint16_t       sw       = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_apdu_split(rapdu, sizeof rapdu, &body, &body_len, &sw));

    TEST_ASSERT_EQUAL_HEX16(ASYMCRED_SW_SUCCESS, sw);
    TEST_ASSERT_EQUAL_size_t(4U, body_len);
    TEST_ASSERT_EQUAL_PTR(rapdu, body);
}

static void test_splits_status_word_only_response(void)
{
    static const uint8_t rapdu[2] = { 0x6AU, 0x82U };

    const uint8_t *body     = NULL;
    size_t         body_len = 1U;
    uint16_t       sw       = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_apdu_split(rapdu, sizeof rapdu, &body, &body_len, &sw));

    TEST_ASSERT_EQUAL_HEX16(0x6A82U, sw);
    TEST_ASSERT_EQUAL_size_t(0U, body_len);
    TEST_ASSERT_NULL(body);
}

static void test_split_rejects_undersized_response(void)
{
    static const uint8_t rapdu[1] = { 0x90U };

    const uint8_t *body     = NULL;
    size_t         body_len = 0U;
    uint16_t       sw       = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_TRUNCATED,
        asymcred_apdu_split(rapdu, sizeof rapdu, &body, &body_len, &sw));
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_builds_case4_short_apdu);
    RUN_TEST(test_build_rejects_empty_body);
    RUN_TEST(test_build_respects_capacity);
    RUN_TEST(test_splits_body_and_status_word);
    RUN_TEST(test_splits_status_word_only_response);
    RUN_TEST(test_split_rejects_undersized_response);

    return UNITY_END();
}
