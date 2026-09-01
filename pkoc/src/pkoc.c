// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "asymcred/asymcred_pkoc.h"

#include "asymcred/asymcred_apdu.h"
#include "asymcred/asymcred_tlv.h"

#include <string.h>

/* PKOC application identifier, spec "Variables": A000000898000001. */
const uint8_t asymcred_pkoc_aid[ASYMCRED_PKOC_AID_LEN] = {
    0xA0U, 0x00U, 0x00U, 0x08U, 0x98U, 0x00U, 0x00U, 0x01U
};

/* SELECT, spec "SELECT Command": 00 A4 04 00 08 <AID> 00. */
#define PKOC_CLA_SELECT 0x00U
#define PKOC_INS_SELECT 0xA4U
#define PKOC_P1_SELECT  0x04U /* select by DF name (AID)    */
#define PKOC_P2_SELECT  0x00U /* first or only occurrence   */

/* AUTHENTICATE command data: 5C 02 <ver> 4C 10 <txid> 4D 20 <reader id>.
 * 4 + 18 + 34 = 56 = the Lc 0x38 the spec fixes. Field order follows the
 * spec's worked example; the spec also states TLV order is not
 * significant, so a card must accept any. */
#define PKOC_AUTH_DATA_LEN 56U

#define PKOC_VERSION_LEN 2U /* one protocol version, on the wire */

/* Record why the transaction died and stop it. Every failure path funnels
 * through here so `state` and `error` can never disagree. */
static asymcred_status_t fail(asymcred_pkoc_t *pkoc, asymcred_status_t err)
{
    pkoc->state = ASYMCRED_PKOC_STATE_FAILED;
    pkoc->error = err;
    return err;
}

static asymcred_status_t begin_common(asymcred_pkoc_t *pkoc,
                                      const asymcred_pkoc_config_t *config,
                                      const asymcred_crypto_t *crypto)
{
    if (pkoc == NULL || config == NULL || crypto == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    /* A non-empty preference list with a NULL pointer would silently
     * negotiate nothing; catch it here rather than at feed time. */
    if (config->supported_version_count != 0U &&
        config->supported_versions == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    /* Verification is not optional plumbing that can degrade to a
     * warning: if the caller asked for it, the primitives must exist. */
    if (config->require_signature &&
        (crypto->sha256 == NULL || crypto->ecdsa_p256_verify == NULL)) {
        return ASYMCRED_ERR_NOT_SUPPORTED;
    }

    (void)memset(pkoc, 0, sizeof(*pkoc));

    pkoc->config = *config;
    pkoc->crypto = *crypto;
    pkoc->state  = ASYMCRED_PKOC_STATE_SELECT;
    pkoc->error  = ASYMCRED_OK;

    return ASYMCRED_OK;
}

asymcred_status_t asymcred_pkoc_begin(asymcred_pkoc_t *pkoc,
                                      const asymcred_pkoc_config_t *config,
                                      const asymcred_crypto_t *crypto)
{
    asymcred_status_t st;

    if (crypto == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }
    if (crypto->rand_bytes == NULL) {
        return ASYMCRED_ERR_NOT_SUPPORTED;
    }

    st = begin_common(pkoc, config, crypto);
    if (st != ASYMCRED_OK) {
        return st;
    }

    st = pkoc->crypto.rand_bytes(pkoc->crypto.user, pkoc->txid,
                                 ASYMCRED_PKOC_TXID_LEN);
    if (st != ASYMCRED_OK) {
        /* No nonce means no freshness, so there is no degraded mode to
         * fall back to - the transaction is over before it started. */
        return fail(pkoc, st);
    }

    return ASYMCRED_OK;
}

asymcred_status_t asymcred_pkoc_begin_with_transaction_id(
    asymcred_pkoc_t *pkoc,
    const asymcred_pkoc_config_t *config,
    const asymcred_crypto_t *crypto,
    const uint8_t txid[ASYMCRED_PKOC_TXID_LEN])
{
    asymcred_status_t st;

    if (txid == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    st = begin_common(pkoc, config, crypto);
    if (st != ASYMCRED_OK) {
        return st;
    }

    (void)memcpy(pkoc->txid, txid, ASYMCRED_PKOC_TXID_LEN);

    return ASYMCRED_OK;
}

bool asymcred_pkoc_pending(const asymcred_pkoc_t *pkoc)
{
    if (pkoc == NULL) {
        return false;
    }

    return pkoc->state == ASYMCRED_PKOC_STATE_SELECT ||
           pkoc->state == ASYMCRED_PKOC_STATE_AUTH;
}

asymcred_pkoc_state_t asymcred_pkoc_state(const asymcred_pkoc_t *pkoc)
{
    return (pkoc == NULL) ? ASYMCRED_PKOC_STATE_FAILED : pkoc->state;
}

asymcred_status_t asymcred_pkoc_error(const asymcred_pkoc_t *pkoc)
{
    return (pkoc == NULL) ? ASYMCRED_ERR_INVALID_ARG : pkoc->error;
}

uint16_t asymcred_pkoc_card_sw(const asymcred_pkoc_t *pkoc)
{
    return (pkoc == NULL) ? 0U : pkoc->card_sw;
}

asymcred_status_t asymcred_pkoc_make_reader_id(
    const uint8_t site_id    [ASYMCRED_PKOC_SITE_ID_LEN],
    const uint8_t location_id[ASYMCRED_PKOC_LOCATION_ID_LEN],
    uint8_t out[ASYMCRED_PKOC_READER_ID_LEN])
{
    if (site_id == NULL || location_id == NULL || out == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    (void)memcpy(out, site_id, ASYMCRED_PKOC_SITE_ID_LEN);
    (void)memcpy(&out[ASYMCRED_PKOC_SITE_ID_LEN], location_id,
                 ASYMCRED_PKOC_LOCATION_ID_LEN);

    return ASYMCRED_OK;
}

/* ---- Command construction ---------------------------------------------- */

static asymcred_status_t build_select(uint8_t *buf, size_t cap,
                                      size_t *written)
{
    return asymcred_apdu_build(PKOC_CLA_SELECT, PKOC_INS_SELECT,
                               PKOC_P1_SELECT, PKOC_P2_SELECT,
                               asymcred_pkoc_aid, ASYMCRED_PKOC_AID_LEN,
                               0x00U, buf, cap, written);
}

static asymcred_status_t build_authenticate(const asymcred_pkoc_t *pkoc,
                                            uint8_t *buf, size_t cap,
                                            size_t *written)
{
    uint8_t           data[PKOC_AUTH_DATA_LEN];
    uint8_t           version[PKOC_VERSION_LEN];
    size_t            pos = 0U;
    asymcred_status_t st;

    version[0] = (uint8_t)(pkoc->version >> 8);
    version[1] = (uint8_t)(pkoc->version & 0xFFU);

    st = asymcred_tlv_put(data, sizeof data, &pos,
                          ASYMCRED_PKOC_TAG_PROTOCOL_VERSION,
                          version, (uint8_t)PKOC_VERSION_LEN);
    if (st != ASYMCRED_OK) {
        return st;
    }

    st = asymcred_tlv_put(data, sizeof data, &pos,
                          ASYMCRED_PKOC_TAG_TRANSACTION_ID,
                          pkoc->txid, (uint8_t)ASYMCRED_PKOC_TXID_LEN);
    if (st != ASYMCRED_OK) {
        return st;
    }

    st = asymcred_tlv_put(data, sizeof data, &pos,
                          ASYMCRED_PKOC_TAG_READER_ID,
                          pkoc->config.reader_id,
                          (uint8_t)ASYMCRED_PKOC_READER_ID_LEN);
    if (st != ASYMCRED_OK) {
        return st;
    }

    return asymcred_apdu_build(ASYMCRED_PKOC_CLA_AUTHENTICATE,
                               ASYMCRED_PKOC_INS_AUTHENTICATE,
                               ASYMCRED_PKOC_P1_AUTHENTICATE,
                               ASYMCRED_PKOC_P2_AUTHENTICATE,
                               data, pos, 0x00U, buf, cap, written);
}

asymcred_status_t asymcred_pkoc_next_apdu(asymcred_pkoc_t *pkoc,
                                          uint8_t *buf, size_t cap,
                                          size_t *written)
{
    if (pkoc == NULL || buf == NULL || written == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    switch (pkoc->state) {
    case ASYMCRED_PKOC_STATE_SELECT:
        return build_select(buf, cap, written);

    case ASYMCRED_PKOC_STATE_AUTH:
        return build_authenticate(pkoc, buf, cap, written);

    case ASYMCRED_PKOC_STATE_COMPLETE:
    case ASYMCRED_PKOC_STATE_FAILED:
    default:
        return ASYMCRED_ERR_INVALID_STATE;
    }
}

/* ---- Version negotiation ------------------------------------------------ */

static uint16_t version_at(const uint8_t *list, size_t index)
{
    size_t off = index * PKOC_VERSION_LEN;

    return (uint16_t)(((uint16_t)list[off] << 8) | (uint16_t)list[off + 1U]);
}

/* Pick the version to run the transaction at.
 *
 * The card lists what it supports, "sorted by largest (most recent)
 * first" (spec, SELECT Response). With no reader preference configured
 * we take the card's first entry - its most recent. With a preference
 * list we walk it in the caller's order and take the first the card
 * also offers, so a reader can pin an older version deliberately. */
static asymcred_status_t negotiate_version(const asymcred_pkoc_t *pkoc,
                                           const uint8_t *card_list,
                                           size_t card_count,
                                           uint16_t *out)
{
    if (card_count == 0U) {
        return ASYMCRED_ERR_BAD_LENGTH;
    }

    if (pkoc->config.supported_version_count == 0U) {
        *out = version_at(card_list, 0U);
        return ASYMCRED_OK;
    }

    for (size_t i = 0U; i < pkoc->config.supported_version_count; i++) {
        uint16_t want = pkoc->config.supported_versions[i];

        for (size_t j = 0U; j < card_count; j++) {
            if (version_at(card_list, j) == want) {
                *out = want;
                return ASYMCRED_OK;
            }
        }
    }

    return ASYMCRED_ERR_VERSION;
}

/* ---- Response handling -------------------------------------------------- */

static asymcred_status_t handle_select_response(asymcred_pkoc_t *pkoc,
                                                const uint8_t *body,
                                                size_t body_len)
{
    asymcred_tlv_t    tlv;
    asymcred_status_t st;
    uint16_t          version = 0U;

    st = asymcred_tlv_find(body, body_len,
                           ASYMCRED_PKOC_TAG_PROTOCOL_VERSION, &tlv);
    if (st != ASYMCRED_OK) {
        return fail(pkoc, st);
    }

    /* The value is a list of 2-byte versions, so anything not a positive
     * multiple of two is malformed rather than merely unexpected. */
    if (tlv.len < PKOC_VERSION_LEN || (tlv.len % PKOC_VERSION_LEN) != 0U) {
        return fail(pkoc, ASYMCRED_ERR_BAD_LENGTH);
    }

    st = negotiate_version(pkoc, tlv.value,
                           (size_t)tlv.len / PKOC_VERSION_LEN, &version);
    if (st != ASYMCRED_OK) {
        return fail(pkoc, st);
    }

    pkoc->version = version;
    pkoc->state   = ASYMCRED_PKOC_STATE_AUTH;

    return ASYMCRED_OK;
}

/* Verify the card's signature over the transaction identifier.
 *
 * Spec flow step 6: the card signs "the received Transaction ID as the
 * input" with ECDSA (FIPS 186-5 section 6) and returns R||S raw. So the
 * signed message is the 16 transaction-identifier bytes exactly - not
 * the reader identifier, and not the AUTHENTICATE command data. */
static asymcred_status_t verify_signature(asymcred_pkoc_t *pkoc)
{
    uint8_t           digest[ASYMCRED_SHA256_LEN];
    asymcred_status_t st;

    st = pkoc->crypto.sha256(pkoc->crypto.user, pkoc->txid,
                             ASYMCRED_PKOC_TXID_LEN, digest);
    if (st != ASYMCRED_OK) {
        return st;
    }

    st = pkoc->crypto.ecdsa_p256_verify(pkoc->crypto.user, pkoc->public_key,
                                        digest, pkoc->signature);
    if (st != ASYMCRED_OK) {
        return st;
    }

    pkoc->signature_verified = true;

    return ASYMCRED_OK;
}

static asymcred_status_t handle_auth_response(asymcred_pkoc_t *pkoc,
                                              const uint8_t *body,
                                              size_t body_len)
{
    asymcred_tlv_t    tlv;
    asymcred_status_t st;

    st = asymcred_tlv_find(body, body_len,
                           ASYMCRED_PKOC_TAG_PUBLIC_KEY, &tlv);
    if (st != ASYMCRED_OK) {
        return fail(pkoc, st);
    }
    if (tlv.len != ASYMCRED_P256_PUBKEY_LEN) {
        return fail(pkoc, ASYMCRED_ERR_BAD_LENGTH);
    }
    /* SEC 1 uncompressed point marker. A compressed point would need
     * decompression the crypto HAL is not asked to provide, and the spec
     * names the field "Uncompressed Public Key ECC P-256". */
    if (tlv.value[0] != 0x04U) {
        return fail(pkoc, ASYMCRED_ERR_BAD_TLV);
    }
    (void)memcpy(pkoc->public_key, tlv.value, ASYMCRED_P256_PUBKEY_LEN);

    st = asymcred_tlv_find(body, body_len,
                           ASYMCRED_PKOC_TAG_SIGNATURE, &tlv);
    if (st == ASYMCRED_OK) {
        if (tlv.len != ASYMCRED_P256_SIG_LEN) {
            return fail(pkoc, ASYMCRED_ERR_BAD_LENGTH);
        }
        (void)memcpy(pkoc->signature, tlv.value, ASYMCRED_P256_SIG_LEN);
        pkoc->have_signature = true;
    } else if (st != ASYMCRED_ERR_MISSING_TLV) {
        return fail(pkoc, st);
    }

    if (pkoc->config.require_signature) {
        if (!pkoc->have_signature) {
            return fail(pkoc, ASYMCRED_ERR_MISSING_TLV);
        }

        st = verify_signature(pkoc);
        if (st != ASYMCRED_OK) {
            return fail(pkoc, st);
        }
    }

    pkoc->state = ASYMCRED_PKOC_STATE_COMPLETE;

    return ASYMCRED_OK;
}

asymcred_status_t asymcred_pkoc_feed(asymcred_pkoc_t *pkoc,
                                     const uint8_t *rapdu, size_t len)
{
    const uint8_t    *body;
    size_t            body_len;
    uint16_t          sw;
    asymcred_status_t st;

    if (pkoc == NULL || rapdu == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    if (!asymcred_pkoc_pending(pkoc)) {
        return ASYMCRED_ERR_INVALID_STATE;
    }

    st = asymcred_apdu_split(rapdu, len, &body, &body_len, &sw);
    if (st != ASYMCRED_OK) {
        return fail(pkoc, st);
    }

    pkoc->card_sw = sw;

    if (sw != ASYMCRED_SW_SUCCESS) {
        /* A refused SELECT is the ordinary "this card is not a PKOC
         * card" answer, and a reader polling mixed credential types
         * needs to tell that apart from a PKOC card that went wrong
         * mid-transaction. */
        return fail(pkoc, (pkoc->state == ASYMCRED_PKOC_STATE_SELECT)
                              ? ASYMCRED_ERR_NO_APPLET
                              : ASYMCRED_ERR_CARD_STATUS);
    }

    if (body_len == 0U) {
        return fail(pkoc, ASYMCRED_ERR_TRUNCATED);
    }

    if (pkoc->state == ASYMCRED_PKOC_STATE_SELECT) {
        return handle_select_response(pkoc, body, body_len);
    }

    return handle_auth_response(pkoc, body, body_len);
}

asymcred_status_t asymcred_pkoc_result(const asymcred_pkoc_t *pkoc,
                                       asymcred_pkoc_result_t *out)
{
    if (pkoc == NULL || out == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    /* Gating on _COMPLETE is what keeps an unverified public key out of
     * a caller's hands: a signature failure moved the machine to
     * _FAILED, and there is no path from there to here. */
    if (pkoc->state != ASYMCRED_PKOC_STATE_COMPLETE) {
        return ASYMCRED_ERR_INVALID_STATE;
    }

    out->version = pkoc->version;
    (void)memcpy(out->public_key, pkoc->public_key, ASYMCRED_P256_PUBKEY_LEN);
    (void)memcpy(out->transaction_id, pkoc->txid, ASYMCRED_PKOC_TXID_LEN);
    (void)memcpy(out->signature, pkoc->signature, ASYMCRED_P256_SIG_LEN);
    out->have_signature     = pkoc->have_signature;
    out->signature_verified = pkoc->signature_verified;

    return ASYMCRED_OK;
}

asymcred_status_t asymcred_pkoc_run(asymcred_pkoc_t *pkoc,
                                    asymcred_pkoc_transceive_fn transceive,
                                    void *user,
                                    asymcred_pkoc_result_t *out)
{
    uint8_t cmd[ASYMCRED_PKOC_MAX_CAPDU];
    uint8_t rsp[ASYMCRED_PKOC_MAX_RAPDU];

    if (pkoc == NULL || transceive == NULL || out == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    while (asymcred_pkoc_pending(pkoc)) {
        size_t            cmd_len = 0U;
        size_t            rsp_len = 0U;
        asymcred_status_t st;

        st = asymcred_pkoc_next_apdu(pkoc, cmd, sizeof cmd, &cmd_len);
        if (st != ASYMCRED_OK) {
            return fail(pkoc, st);
        }

        st = transceive(user, cmd, cmd_len, rsp, sizeof rsp, &rsp_len);
        if (st != ASYMCRED_OK) {
            return fail(pkoc, st);
        }

        st = asymcred_pkoc_feed(pkoc, rsp, rsp_len);
        if (st != ASYMCRED_OK) {
            return st; /* feed already recorded the failure */
        }
    }

    return asymcred_pkoc_result(pkoc, out);
}
