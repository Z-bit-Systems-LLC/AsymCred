// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "asymcred/asymcred_tlv.h"

#include <string.h>

asymcred_status_t asymcred_tlv_iter_init(asymcred_tlv_iter_t *it,
                                         const uint8_t *buf, size_t len)
{
    if (it == NULL || (buf == NULL && len != 0U)) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    it->buf = buf;
    it->len = len;
    it->pos = 0U;

    return ASYMCRED_OK;
}

asymcred_status_t asymcred_tlv_iter_next(asymcred_tlv_iter_t *it,
                                         asymcred_tlv_t *out)
{
    if (it == NULL || out == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    /* Clean end of sequence. A single trailing byte cannot be a record
     * (a tag with no length), so treat it as the end rather than as
     * corruption — some cards pad. */
    if (it->pos + 2U > it->len) {
        return ASYMCRED_ERR_TRUNCATED;
    }

    uint8_t tag = it->buf[it->pos];
    uint8_t len = it->buf[it->pos + 1U];

    /* The PKOC dialect is one-byte lengths only; 0x80..0xFF would be a
     * BER long form we deliberately do not accept. Rejecting it keeps a
     * malformed record from being read as a short one. */
    if (len >= 0x80U) {
        return ASYMCRED_ERR_BAD_TLV;
    }

    if (it->pos + 2U + (size_t)len > it->len) {
        return ASYMCRED_ERR_BAD_TLV;
    }

    out->tag   = tag;
    out->len   = len;
    out->value = (len == 0U) ? NULL : &it->buf[it->pos + 2U];

    it->pos += 2U + (size_t)len;

    return ASYMCRED_OK;
}

asymcred_status_t asymcred_tlv_find(const uint8_t *buf, size_t len,
                                    uint8_t tag, asymcred_tlv_t *out)
{
    asymcred_tlv_iter_t it;
    asymcred_tlv_t      rec;
    asymcred_status_t   st;

    if (out == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    st = asymcred_tlv_iter_init(&it, buf, len);
    if (st != ASYMCRED_OK) {
        return st;
    }

    for (;;) {
        st = asymcred_tlv_iter_next(&it, &rec);

        if (st == ASYMCRED_ERR_TRUNCATED) {
            return ASYMCRED_ERR_MISSING_TLV; /* walked the whole sequence */
        }
        if (st != ASYMCRED_OK) {
            return st;                       /* malformed — report as-is  */
        }

        /* Unrecognised tags are skipped, per the spec's forward-
         * compatibility note. */
        if (rec.tag == tag) {
            *out = rec;
            return ASYMCRED_OK;
        }
    }
}

asymcred_status_t asymcred_tlv_put(uint8_t *buf, size_t cap, size_t *pos,
                                   uint8_t tag,
                                   const uint8_t *value, uint8_t len)
{
    if (buf == NULL || pos == NULL || (value == NULL && len != 0U)) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    if (*pos > cap || cap - *pos < 2U + (size_t)len) {
        return ASYMCRED_ERR_BUFFER_TOO_SMALL;
    }

    buf[*pos]      = tag;
    buf[*pos + 1U] = len;

    if (len != 0U) {
        (void)memcpy(&buf[*pos + 2U], value, (size_t)len);
    }

    *pos += 2U + (size_t)len;

    return ASYMCRED_OK;
}
