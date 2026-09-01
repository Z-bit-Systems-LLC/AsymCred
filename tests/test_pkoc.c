// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "asymcred/asymcred_apdu.h"
#include "asymcred/asymcred_pkoc.h"
#include "support/test_crypto.h"
#include "unity.h"

#include <string.h>

/* Vectors from the PSIA PKOC NFC Card Specification v1.1, section
 * "Example". The whole exchange is reproduced byte for byte.
 *
 * The example is known good, not merely transcribed: the signature below
 * verifies as ECDSA-P256-SHA256 over the 16-byte transaction ID with the
 * public key below (checked independently with openssl). That is what
 * pins down *what* the card signs - the transaction ID alone, not the
 * reader identifier and not the command data - which the spec states in
 * prose at flow step 6 but nowhere shows as a computable fact. */

static const uint8_t SPEC_TXID[16] = {
    0x6FU, 0xCFU, 0x50U, 0x12U, 0xB2U, 0x24U, 0x04U, 0x3BU,
    0x09U, 0x35U, 0x0AU, 0x4FU, 0xC5U, 0xE5U, 0x6AU, 0x8FU
};

static const uint8_t SPEC_READER_ID[32] = {
    0x7AU, 0x25U, 0x43U, 0x2AU, 0x46U, 0x2DU, 0x4AU, 0x40U,
    0x4EU, 0x63U, 0x52U, 0x66U, 0x55U, 0x6AU, 0x58U, 0x6EU,
    0xDFU, 0xEEU, 0x80U, 0x22U, 0x96U, 0x63U, 0x11U, 0xEDU,
    0xA1U, 0xEBU, 0x02U, 0x42U, 0xACU, 0x12U, 0x00U, 0x02U
};

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

static const uint8_t SPEC_SIG[64] = {
    0xB9U, 0x86U, 0x13U, 0x07U, 0x0CU, 0x78U, 0x01U, 0x0BU,
    0x04U, 0xEDU, 0x30U, 0x6DU, 0x14U, 0x3FU, 0x94U, 0xEEU,
    0x6DU, 0xC4U, 0xECU, 0xA2U, 0x58U, 0x5BU, 0x62U, 0x14U,
    0x05U, 0x73U, 0x1FU, 0xB3U, 0xA5U, 0x3CU, 0xD8U, 0x77U,
    0xA2U, 0x16U, 0x85U, 0xDEU, 0x18U, 0x43U, 0x5DU, 0xA7U,
    0xCBU, 0xCCU, 0x38U, 0xF1U, 0xD9U, 0x26U, 0x30U, 0x0AU,
    0x45U, 0x4EU, 0xFEU, 0xE3U, 0x59U, 0x4CU, 0xECU, 0x5EU,
    0xFFU, 0xE2U, 0x8CU, 0x7FU, 0xEAU, 0xC0U, 0x3DU, 0x7DU
};

/* SHA-256 of SPEC_TXID, computed independently (openssl). The digest the
 * state machine hands to verification must equal this - that is the
 * assertion that catches "we hashed the wrong thing". */
static const uint8_t SPEC_TXID_DIGEST[32] = {
    0x40U, 0xCAU, 0x58U, 0xE5U, 0x63U, 0x1EU, 0x24U, 0xEAU,
    0xF9U, 0x65U, 0xCBU, 0x1AU, 0x92U, 0x25U, 0xE5U, 0x1FU,
    0x9BU, 0x91U, 0x72U, 0xE0U, 0x6BU, 0x3EU, 0xDAU, 0x1EU,
    0x54U, 0xE3U, 0x6DU, 0x3EU, 0xDCU, 0xE4U, 0x78U, 0x08U
};

/* "The reader sends SELECT APDU to CE" */
static const uint8_t SPEC_SELECT_CAPDU[14] = {
    0x00U, 0xA4U, 0x04U, 0x00U, 0x08U,
    0xA0U, 0x00U, 0x00U, 0x08U, 0x98U, 0x00U, 0x00U, 0x01U,
    0x00U
};

/* "The card sends Protocol Version + Success Response to RE" */
static const uint8_t SPEC_SELECT_RAPDU[6] = {
    0x5CU, 0x02U, 0x01U, 0x00U, 0x90U, 0x00U
};

static asymcred_crypto_t crypto;
static test_crypto_t     crypto_state;
static asymcred_pkoc_t   pkoc;

void setUp(void)
{
    test_crypto_init(&crypto, &crypto_state);
}

void tearDown(void) { }

static asymcred_pkoc_config_t spec_config(bool require_signature)
{
    asymcred_pkoc_config_t cfg;

    (void)memset(&cfg, 0, sizeof cfg);
    (void)memcpy(cfg.reader_id, SPEC_READER_ID, sizeof SPEC_READER_ID);
    cfg.require_signature = require_signature;

    return cfg;
}

/* Assemble the card's AUTHENTICATE response: 5A 41 <key> 9E 40 <sig> SW. */
static size_t build_auth_rapdu(uint8_t *buf, const uint8_t *pubkey,
                               const uint8_t *sig, uint16_t sw)
{
    size_t pos = 0U;

    if (pubkey != NULL) {
        buf[pos++] = 0x5AU;
        buf[pos++] = 0x41U;
        (void)memcpy(&buf[pos], pubkey, 65U);
        pos += 65U;
    }
    if (sig != NULL) {
        buf[pos++] = 0x9EU;
        buf[pos++] = 0x40U;
        (void)memcpy(&buf[pos], sig, 64U);
        pos += 64U;
    }

    buf[pos++] = (uint8_t)(sw >> 8);
    buf[pos++] = (uint8_t)(sw & 0xFFU);

    return pos;
}

/* Drive a transaction as far as the AUTHENTICATE command. */
static void advance_to_auth(bool require_signature)
{
    uint8_t buf[ASYMCRED_PKOC_MAX_CAPDU];
    size_t  written = 0U;

    asymcred_pkoc_config_t cfg = spec_config(require_signature);

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));
    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_next_apdu(&pkoc, buf, sizeof buf, &written));
    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_feed(&pkoc, SPEC_SELECT_RAPDU,
                           sizeof SPEC_SELECT_RAPDU));
    TEST_ASSERT_EQUAL(ASYMCRED_PKOC_STATE_AUTH, asymcred_pkoc_state(&pkoc));
}

/* ---- The spec's worked example, byte for byte -------------------------- */

static void test_select_apdu_matches_spec(void)
{
    uint8_t buf[ASYMCRED_PKOC_MAX_CAPDU];
    size_t  written = 0U;

    asymcred_pkoc_config_t cfg = spec_config(true);

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_next_apdu(&pkoc, buf, sizeof buf, &written));

    TEST_ASSERT_EQUAL_size_t(sizeof SPEC_SELECT_CAPDU, written);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(SPEC_SELECT_CAPDU, buf, written);
}

static void test_authenticate_apdu_matches_spec(void)
{
    /* The full 62-byte AUTHENTICATE from the spec's example, including
     * its TLV ordering (version, transaction ID, reader identifier). */
    static const uint8_t expect[62] = {
        0x80U, 0x80U, 0x00U, 0x01U, 0x38U,
        0x5CU, 0x02U, 0x01U, 0x00U,
        0x4CU, 0x10U,
        0x6FU, 0xCFU, 0x50U, 0x12U, 0xB2U, 0x24U, 0x04U, 0x3BU,
        0x09U, 0x35U, 0x0AU, 0x4FU, 0xC5U, 0xE5U, 0x6AU, 0x8FU,
        0x4DU, 0x20U,
        0x7AU, 0x25U, 0x43U, 0x2AU, 0x46U, 0x2DU, 0x4AU, 0x40U,
        0x4EU, 0x63U, 0x52U, 0x66U, 0x55U, 0x6AU, 0x58U, 0x6EU,
        0xDFU, 0xEEU, 0x80U, 0x22U, 0x96U, 0x63U, 0x11U, 0xEDU,
        0xA1U, 0xEBU, 0x02U, 0x42U, 0xACU, 0x12U, 0x00U, 0x02U,
        0x00U
    };

    uint8_t buf[ASYMCRED_PKOC_MAX_CAPDU];
    size_t  written = 0U;

    advance_to_auth(true);

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_next_apdu(&pkoc, buf, sizeof buf, &written));

    TEST_ASSERT_EQUAL_size_t(sizeof expect, written);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, buf, written);
}

static void test_full_transaction_completes(void)
{
    uint8_t                rapdu[ASYMCRED_PKOC_MAX_RAPDU];
    asymcred_pkoc_result_t res;
    size_t                 len;

    advance_to_auth(true);

    len = build_auth_rapdu(rapdu, SPEC_PUBKEY, SPEC_SIG,
                           ASYMCRED_SW_SUCCESS);
    TEST_ASSERT_EQUAL_size_t(135U, len);

    TEST_ASSERT_EQUAL(ASYMCRED_OK, asymcred_pkoc_feed(&pkoc, rapdu, len));
    TEST_ASSERT_EQUAL(ASYMCRED_PKOC_STATE_COMPLETE,
                      asymcred_pkoc_state(&pkoc));
    TEST_ASSERT_FALSE(asymcred_pkoc_pending(&pkoc));

    TEST_ASSERT_EQUAL(ASYMCRED_OK, asymcred_pkoc_result(&pkoc, &res));
    TEST_ASSERT_EQUAL_HEX16(ASYMCRED_PKOC_VERSION_1_0, res.version);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(SPEC_PUBKEY, res.public_key, 65);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(SPEC_SIG, res.signature, 64);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(SPEC_TXID, res.transaction_id, 16);
    TEST_ASSERT_TRUE(res.have_signature);
    TEST_ASSERT_TRUE(res.signature_verified);
}

/* The signed message is the transaction ID and nothing else. */
static void test_signature_is_verified_over_transaction_id(void)
{
    uint8_t rapdu[ASYMCRED_PKOC_MAX_RAPDU];
    size_t  len;

    advance_to_auth(true);

    len = build_auth_rapdu(rapdu, SPEC_PUBKEY, SPEC_SIG,
                           ASYMCRED_SW_SUCCESS);
    TEST_ASSERT_EQUAL(ASYMCRED_OK, asymcred_pkoc_feed(&pkoc, rapdu, len));

    TEST_ASSERT_TRUE(crypto_state.verify_called);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(SPEC_TXID_DIGEST,
                                  crypto_state.last_digest, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(SPEC_PUBKEY, crypto_state.last_pub, 65);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(SPEC_SIG, crypto_state.last_sig, 64);
}

/* ---- Failure paths ------------------------------------------------------ */

static void test_bad_signature_fails_and_withholds_result(void)
{
    uint8_t                rapdu[ASYMCRED_PKOC_MAX_RAPDU];
    asymcred_pkoc_result_t res;
    size_t                 len;

    advance_to_auth(true);
    crypto_state.verify_result = ASYMCRED_ERR_BAD_SIGNATURE;

    len = build_auth_rapdu(rapdu, SPEC_PUBKEY, SPEC_SIG,
                           ASYMCRED_SW_SUCCESS);

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BAD_SIGNATURE,
                      asymcred_pkoc_feed(&pkoc, rapdu, len));
    TEST_ASSERT_EQUAL(ASYMCRED_PKOC_STATE_FAILED,
                      asymcred_pkoc_state(&pkoc));
    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BAD_SIGNATURE,
                      asymcred_pkoc_error(&pkoc));

    /* The public key must not be reachable: a caller that ignored the
     * return value still cannot derive a credential from it. */
    TEST_ASSERT_EQUAL(ASYMCRED_ERR_INVALID_STATE,
                      asymcred_pkoc_result(&pkoc, &res));
}

static void test_missing_signature_fails_when_required(void)
{
    uint8_t rapdu[ASYMCRED_PKOC_MAX_RAPDU];
    size_t  len;

    advance_to_auth(true);

    len = build_auth_rapdu(rapdu, SPEC_PUBKEY, NULL, ASYMCRED_SW_SUCCESS);

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_MISSING_TLV,
                      asymcred_pkoc_feed(&pkoc, rapdu, len));
    TEST_ASSERT_EQUAL(ASYMCRED_PKOC_STATE_FAILED,
                      asymcred_pkoc_state(&pkoc));
}

/* Enrolment / bench mode: read the key, do not pretend it is trusted. */
static void test_identification_only_skips_verification(void)
{
    uint8_t                rapdu[ASYMCRED_PKOC_MAX_RAPDU];
    asymcred_pkoc_result_t res;
    size_t                 len;

    advance_to_auth(false);

    len = build_auth_rapdu(rapdu, SPEC_PUBKEY, NULL, ASYMCRED_SW_SUCCESS);

    TEST_ASSERT_EQUAL(ASYMCRED_OK, asymcred_pkoc_feed(&pkoc, rapdu, len));
    TEST_ASSERT_EQUAL(ASYMCRED_OK, asymcred_pkoc_result(&pkoc, &res));

    TEST_ASSERT_FALSE(crypto_state.verify_called);
    TEST_ASSERT_FALSE(res.have_signature);
    TEST_ASSERT_FALSE(res.signature_verified);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(SPEC_PUBKEY, res.public_key, 65);
}

static void test_select_refused_reports_no_applet(void)
{
    /* 6A82 - file not found; what a non-PKOC card answers. */
    static const uint8_t rapdu[2] = { 0x6AU, 0x82U };

    asymcred_pkoc_config_t cfg = spec_config(true);

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_NO_APPLET,
                      asymcred_pkoc_feed(&pkoc, rapdu, sizeof rapdu));
    TEST_ASSERT_EQUAL_HEX16(0x6A82U, asymcred_pkoc_card_sw(&pkoc));
}

static void test_authenticate_card_error_is_reported(void)
{
    uint8_t rapdu[ASYMCRED_PKOC_MAX_RAPDU];
    size_t  len;

    advance_to_auth(true);

    /* 6985 - the card rejected the protocol version we selected. */
    len = build_auth_rapdu(rapdu, NULL, NULL, ASYMCRED_SW_BAD_VERSION);

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_CARD_STATUS,
                      asymcred_pkoc_feed(&pkoc, rapdu, len));
    TEST_ASSERT_EQUAL_HEX16(ASYMCRED_SW_BAD_VERSION,
                            asymcred_pkoc_card_sw(&pkoc));
}

static void test_short_public_key_is_rejected(void)
{
    uint8_t rapdu[ASYMCRED_PKOC_MAX_RAPDU];
    size_t  pos = 0U;

    advance_to_auth(true);

    rapdu[pos++] = 0x5AU;
    rapdu[pos++] = 0x20U; /* 32 bytes - not a 65-byte uncompressed point */
    (void)memset(&rapdu[pos], 0x11U, 32U);
    pos += 32U;
    rapdu[pos++] = 0x90U;
    rapdu[pos++] = 0x00U;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BAD_LENGTH,
                      asymcred_pkoc_feed(&pkoc, rapdu, pos));
}

static void test_compressed_public_key_is_rejected(void)
{
    uint8_t rapdu[ASYMCRED_PKOC_MAX_RAPDU];
    uint8_t key[65];
    size_t  len;

    advance_to_auth(true);

    (void)memcpy(key, SPEC_PUBKEY, sizeof key);
    key[0] = 0x02U; /* compressed point marker */

    len = build_auth_rapdu(rapdu, key, SPEC_SIG, ASYMCRED_SW_SUCCESS);

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BAD_TLV,
                      asymcred_pkoc_feed(&pkoc, rapdu, len));
}

/* ---- Version negotiation ------------------------------------------------ */

static void test_multiple_versions_takes_card_preference_by_default(void)
{
    /* Card offers 1.1 then 1.0, "sorted by largest (most recent) first". */
    static const uint8_t rapdu[8] = {
        0x5CU, 0x04U, 0x01U, 0x01U, 0x01U, 0x00U, 0x90U, 0x00U
    };

    asymcred_pkoc_config_t cfg = spec_config(true);

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));
    TEST_ASSERT_EQUAL(ASYMCRED_OK,
                      asymcred_pkoc_feed(&pkoc, rapdu, sizeof rapdu));

    uint8_t buf[ASYMCRED_PKOC_MAX_CAPDU];
    size_t  written = 0U;
    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_next_apdu(&pkoc, buf, sizeof buf, &written));

    /* Version TLV rides at offset 5: 5C 02 01 01. */
    TEST_ASSERT_EQUAL_HEX8(0x01U, buf[7]);
    TEST_ASSERT_EQUAL_HEX8(0x01U, buf[8]);
}

static void test_reader_preference_can_pin_an_older_version(void)
{
    static const uint8_t rapdu[8] = {
        0x5CU, 0x04U, 0x01U, 0x01U, 0x01U, 0x00U, 0x90U, 0x00U
    };
    static const uint16_t prefer_1_0[] = { ASYMCRED_PKOC_VERSION_1_0 };

    asymcred_pkoc_config_t cfg = spec_config(true);
    cfg.supported_versions      = prefer_1_0;
    cfg.supported_version_count = 1U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));
    TEST_ASSERT_EQUAL(ASYMCRED_OK,
                      asymcred_pkoc_feed(&pkoc, rapdu, sizeof rapdu));

    uint8_t buf[ASYMCRED_PKOC_MAX_CAPDU];
    size_t  written = 0U;
    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_next_apdu(&pkoc, buf, sizeof buf, &written));

    TEST_ASSERT_EQUAL_HEX8(0x01U, buf[7]);
    TEST_ASSERT_EQUAL_HEX8(0x00U, buf[8]);
}

static void test_no_common_version_fails(void)
{
    static const uint16_t prefer_9_9[] = { ASYMCRED_PKOC_VERSION(9, 9) };

    asymcred_pkoc_config_t cfg = spec_config(true);
    cfg.supported_versions      = prefer_9_9;
    cfg.supported_version_count = 1U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_VERSION,
        asymcred_pkoc_feed(&pkoc, SPEC_SELECT_RAPDU,
                           sizeof SPEC_SELECT_RAPDU));
    TEST_ASSERT_EQUAL(ASYMCRED_PKOC_STATE_FAILED,
                      asymcred_pkoc_state(&pkoc));
}

static void test_odd_version_list_is_rejected(void)
{
    /* Three bytes cannot be a list of 2-byte versions. */
    static const uint8_t rapdu[7] = {
        0x5CU, 0x03U, 0x01U, 0x00U, 0x01U, 0x90U, 0x00U
    };

    asymcred_pkoc_config_t cfg = spec_config(true);

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BAD_LENGTH,
                      asymcred_pkoc_feed(&pkoc, rapdu, sizeof rapdu));
}

/* Unknown TLVs must be ignored, per the spec's forward-compatibility note. */
static void test_unknown_tlvs_are_ignored(void)
{
    static const uint8_t rapdu[11] = {
        0xDFU, 0x03U, 0xAAU, 0xBBU, 0xCCU, /* unrecognised, must be skipped */
        0x5CU, 0x02U, 0x01U, 0x00U,
        0x90U, 0x00U
    };

    asymcred_pkoc_config_t cfg = spec_config(true);

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));
    TEST_ASSERT_EQUAL(ASYMCRED_OK,
                      asymcred_pkoc_feed(&pkoc, rapdu, sizeof rapdu));
    TEST_ASSERT_EQUAL(ASYMCRED_PKOC_STATE_AUTH, asymcred_pkoc_state(&pkoc));
}

/* ---- Contract ----------------------------------------------------------- */

static void test_begin_draws_a_random_transaction_id(void)
{
    asymcred_pkoc_config_t cfg = spec_config(true);
    uint8_t                buf[ASYMCRED_PKOC_MAX_CAPDU];
    size_t                 written = 0U;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
                      asymcred_pkoc_begin(&pkoc, &cfg, &crypto));
    TEST_ASSERT_TRUE(crypto_state.rand_called);

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_feed(&pkoc, SPEC_SELECT_RAPDU,
                           sizeof SPEC_SELECT_RAPDU));
    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_next_apdu(&pkoc, buf, sizeof buf, &written));

    /* The stub RNG fills 0xA5; the transaction ID TLV starts at offset 11. */
    for (size_t i = 0U; i < 16U; i++) {
        TEST_ASSERT_EQUAL_HEX8(0xA5U, buf[11U + i]);
    }
}

static void test_verification_without_primitives_is_refused(void)
{
    asymcred_pkoc_config_t cfg = spec_config(true);

    crypto.ecdsa_p256_verify = NULL;

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_NOT_SUPPORTED,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));
}

static void test_no_apdu_after_completion(void)
{
    uint8_t rapdu[ASYMCRED_PKOC_MAX_RAPDU];
    uint8_t buf[ASYMCRED_PKOC_MAX_CAPDU];
    size_t  written = 0U;
    size_t  len;

    advance_to_auth(true);
    len = build_auth_rapdu(rapdu, SPEC_PUBKEY, SPEC_SIG,
                           ASYMCRED_SW_SUCCESS);
    TEST_ASSERT_EQUAL(ASYMCRED_OK, asymcred_pkoc_feed(&pkoc, rapdu, len));

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_INVALID_STATE,
        asymcred_pkoc_next_apdu(&pkoc, buf, sizeof buf, &written));
    TEST_ASSERT_EQUAL(ASYMCRED_ERR_INVALID_STATE,
                      asymcred_pkoc_feed(&pkoc, rapdu, len));
}

static void test_next_apdu_rejects_small_buffer(void)
{
    uint8_t buf[8];
    size_t  written = 0U;

    asymcred_pkoc_config_t cfg = spec_config(true);

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));

    TEST_ASSERT_EQUAL(ASYMCRED_ERR_BUFFER_TOO_SMALL,
        asymcred_pkoc_next_apdu(&pkoc, buf, sizeof buf, &written));
}

static void test_make_reader_id_concatenates_halves(void)
{
    uint8_t site[16], location[16], out[32];

    (void)memset(site, 0x11U, sizeof site);
    (void)memset(location, 0x22U, sizeof location);

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
                      asymcred_pkoc_make_reader_id(site, location, out));

    for (size_t i = 0U; i < 16U; i++) {
        TEST_ASSERT_EQUAL_HEX8(0x11U, out[i]);
        TEST_ASSERT_EQUAL_HEX8(0x22U, out[16U + i]);
    }
}

/* ---- The blocking convenience wrapper ---------------------------------- */

typedef struct {
    int step;
} fake_card_t;

static asymcred_status_t fake_card(void *user,
                                   const uint8_t *cmd, size_t cmd_len,
                                   uint8_t *rsp, size_t rsp_cap,
                                   size_t *rsp_len)
{
    fake_card_t *card = (fake_card_t *)user;

    (void)cmd;
    (void)cmd_len;
    (void)rsp_cap;

    if (card->step == 0) {
        (void)memcpy(rsp, SPEC_SELECT_RAPDU, sizeof SPEC_SELECT_RAPDU);
        *rsp_len = sizeof SPEC_SELECT_RAPDU;
    } else {
        *rsp_len = build_auth_rapdu(rsp, SPEC_PUBKEY, SPEC_SIG,
                                    ASYMCRED_SW_SUCCESS);
    }

    card->step++;

    return ASYMCRED_OK;
}

static void test_run_drives_the_whole_exchange(void)
{
    asymcred_pkoc_config_t cfg  = spec_config(true);
    fake_card_t            card = { 0 };
    asymcred_pkoc_result_t res;

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
        asymcred_pkoc_begin_with_transaction_id(&pkoc, &cfg, &crypto,
                                                SPEC_TXID));

    TEST_ASSERT_EQUAL(ASYMCRED_OK,
                      asymcred_pkoc_run(&pkoc, fake_card, &card, &res));

    TEST_ASSERT_EQUAL_INT(2, card.step);
    TEST_ASSERT_TRUE(res.signature_verified);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(SPEC_PUBKEY, res.public_key, 65);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_select_apdu_matches_spec);
    RUN_TEST(test_authenticate_apdu_matches_spec);
    RUN_TEST(test_full_transaction_completes);
    RUN_TEST(test_signature_is_verified_over_transaction_id);

    RUN_TEST(test_bad_signature_fails_and_withholds_result);
    RUN_TEST(test_missing_signature_fails_when_required);
    RUN_TEST(test_identification_only_skips_verification);
    RUN_TEST(test_select_refused_reports_no_applet);
    RUN_TEST(test_authenticate_card_error_is_reported);
    RUN_TEST(test_short_public_key_is_rejected);
    RUN_TEST(test_compressed_public_key_is_rejected);

    RUN_TEST(test_multiple_versions_takes_card_preference_by_default);
    RUN_TEST(test_reader_preference_can_pin_an_older_version);
    RUN_TEST(test_no_common_version_fails);
    RUN_TEST(test_odd_version_list_is_rejected);
    RUN_TEST(test_unknown_tlvs_are_ignored);

    RUN_TEST(test_begin_draws_a_random_transaction_id);
    RUN_TEST(test_verification_without_primitives_is_refused);
    RUN_TEST(test_no_apdu_after_completion);
    RUN_TEST(test_next_apdu_rejects_small_buffer);
    RUN_TEST(test_make_reader_id_concatenates_halves);

    RUN_TEST(test_run_drives_the_whole_exchange);

    return UNITY_END();
}
