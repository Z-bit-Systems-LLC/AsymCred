// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "asymcred/asymcred_tlv.h"
#include "unity.h"

#include <string.h>

void setUp(void) { }
void tearDown(void) { }

static void test_iterates_records_in_order(void)
{
    static const uint8_t buf[] = {
        0x5CU, 0x02U, 0x01U, 0x00U,
        0x4CU, 0x03U, 0xAAU, 0xBBU, 0xCCU
    };

    asymcred_tlv_iter_t it;
    asymcred_tlv_t      rec;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
                      asymcred_tlv_iter_init(&it, buf, sizeof buf));

    TEST_ASSERT_EQUAL(ASYMCRED_OK, asymcred_tlv_iter_next(&it, &rec));
    TEST_ASSERT_EQUAL_HEX8(0x5CU, rec.tag);
    TEST_ASSERT_EQUAL_UINT8(2U, rec.len);
    TEST_ASSERT_EQUAL_HEX8(0x01U, rec.value[0]);

    TEST_ASSERT_EQUAL(ASYMCRED_OK, asymcred_tlv_iter_next(&it, &rec));
    TEST_ASSERT_EQUAL_HEX8(0x4CU, rec.tag);
    TEST_ASSERT_EQUAL_UINT8(3U, rec.len);
    TEST_ASSERT_EQUAL_HEX8(0xCCU, rec.value[2]);

    /* Clean exhaustion, not corruption. */
    TEST_ASSERT_EQUAL(ASYMCRED_ERR_TRUNCATED,
                      asymcred_tlv_iter_next(&it, &rec));
}

static void test_find_skips_unknown_tags(void)
{
    static const uint8_t buf[] = {
        0xDFU, 0x02U, 0x00U, 0x00U,  /* unrecognised */
        0x9EU, 0x01U, 0x42U
    };

    asymcred_tlv_t rec;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
                      asymcred_tlv_find(buf, sizeof buf, 0x9EU, &rec));
    TEST_ASSERT_EQUAL_UINT8(1U, rec.len);
    TEST_ASSERT_EQUAL_HEX8(0x42U, rec.value[0]);
}

static void test_find_reports_missing_tag(void)
{
    static const uint8_t buf[] = { 0x5CU, 0x02U, 0x01U, 0x00U };

    asymcred_tlv_t rec;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_MISSING_TLV,
                      asymcred_tlv_find(buf, sizeof buf, 0x9EU, &rec));
}

static void test_length_overrunning_the_buffer_is_rejected(void)
{
    /* Claims 16 bytes of value with only 2 present. */
    static const uint8_t buf[] = { 0x5AU, 0x10U, 0x01U, 0x02U };

    asymcred_tlv_t rec;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BAD_TLV,
                      asymcred_tlv_find(buf, sizeof buf, 0x5AU, &rec));
}

static void test_long_form_length_is_rejected(void)
{
    /* 0x81 would be a BER long form; the PKOC dialect has no such thing,
     * and reading it as a 129-byte short length would be worse. */
    static const uint8_t buf[] = { 0x5AU, 0x81U, 0x01U, 0x02U };

    asymcred_tlv_t rec;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BAD_TLV,
                      asymcred_tlv_find(buf, sizeof buf, 0x5AU, &rec));
}

static void test_trailing_stray_byte_ends_cleanly(void)
{
    static const uint8_t buf[] = { 0x5CU, 0x02U, 0x01U, 0x00U, 0xFFU };

    asymcred_tlv_t rec;

    /* The stray byte cannot start a record, so the tag simply is not
     * found - the sequence is not reported as malformed. */
    TEST_ASSERT_EQUAL(ASYMCRED_ERR_MISSING_TLV,
                      asymcred_tlv_find(buf, sizeof buf, 0x9EU, &rec));
}

static void test_put_appends_records(void)
{
    static const uint8_t value[3] = { 0xAAU, 0xBBU, 0xCCU };
    static const uint8_t expect[] = {
        0x5CU, 0x02U, 0x01U, 0x00U,
        0x4CU, 0x03U, 0xAAU, 0xBBU, 0xCCU
    };

    uint8_t buf[16];
    size_t  pos = 0U;

    static const uint8_t version[2] = { 0x01U, 0x00U };

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_tlv_put(buf, sizeof buf, &pos, 0x5CU, version, 2U));
    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_tlv_put(buf, sizeof buf, &pos, 0x4CU, value, 3U));

    TEST_ASSERT_EQUAL_size_t(sizeof expect, pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, buf, pos);
}

static void test_put_respects_capacity(void)
{
    static const uint8_t value[4] = { 1U, 2U, 3U, 4U };

    uint8_t buf[5];
    size_t  pos = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BUFFER_TOO_SMALL,
        asymcred_tlv_put(buf, sizeof buf, &pos, 0x4CU, value, 4U));
    TEST_ASSERT_EQUAL_size_t(0U, pos);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_iterates_records_in_order);
    RUN_TEST(test_find_skips_unknown_tags);
    RUN_TEST(test_find_reports_missing_tag);
    RUN_TEST(test_length_overrunning_the_buffer_is_rejected);
    RUN_TEST(test_long_form_length_is_rejected);
    RUN_TEST(test_trailing_stray_byte_ends_cleanly);
    RUN_TEST(test_put_appends_records);
    RUN_TEST(test_put_respects_capacity);

    return UNITY_END();
}
