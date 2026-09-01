// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "asymcred/asymcred_apdu.h"

#include <string.h>

asymcred_status_t asymcred_apdu_build(uint8_t cla, uint8_t ins,
                                      uint8_t p1, uint8_t p2,
                                      const uint8_t *data, size_t data_len,
                                      uint8_t le,
                                      uint8_t *buf, size_t cap,
                                      size_t *written)
{
    if (buf == NULL || written == NULL || data == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    /* Short Lc only, and case 4 only — see the header. */
    if (data_len == 0U || data_len > 255U) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    size_t need = 5U + data_len + 1U; /* header + Lc + data + Le */
    if (cap < need) {
        return ASYMCRED_ERR_BUFFER_TOO_SMALL;
    }

    buf[0] = cla;
    buf[1] = ins;
    buf[2] = p1;
    buf[3] = p2;
    buf[4] = (uint8_t)data_len;
    (void)memcpy(&buf[5], data, data_len);
    buf[5U + data_len] = le;

    *written = need;

    return ASYMCRED_OK;
}

asymcred_status_t asymcred_apdu_split(const uint8_t *rapdu, size_t len,
                                      const uint8_t **body, size_t *body_len,
                                      uint16_t *sw)
{
    if (rapdu == NULL || body == NULL || body_len == NULL || sw == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    if (len < 2U) {
        return ASYMCRED_ERR_TRUNCATED;
    }

    *sw = (uint16_t)(((uint16_t)rapdu[len - 2U] << 8) | (uint16_t)rapdu[len - 1U]);

    *body_len = len - 2U;
    *body     = (*body_len == 0U) ? NULL : rapdu;

    return ASYMCRED_OK;
}
