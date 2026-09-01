// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "asymcred/asymcred_pkoc.h"

#include <string.h>

/* Credential derivation, spec "PKOC- Credential Creation and
 * Provisioning" item 3: the credential is the X component of the public
 * key, truncated to what the panel can carry.
 *
 *   - 256 bits: all of X, for systems with bi-directional comms.
 *   - 75 bits:  the low 75 bits of X (recommended for legacy panels).
 *   - 64 bits:  the low 64 bits of X (the stated minimum).
 *
 * "Lower N bits" is the low-order end of X read as a big-endian integer,
 * so every form is a suffix of the 32 X bytes - and the 75-bit form
 * additionally keeps 3 bits of the byte before that suffix.
 *
 * Output is right-aligned big-endian with the unused leading bits
 * cleared, which is the shape an OSDP osdp_RAW payload wants. */

/* X starts one byte past the SEC 1 0x04 uncompressed-point marker. */
#define PKOC_X_OFFSET 1U
#define PKOC_X_LEN    32U

asymcred_status_t asymcred_pkoc_credential(
    const uint8_t public_key[ASYMCRED_P256_PUBKEY_LEN],
    asymcred_pkoc_cred_size_t size,
    uint8_t *out, size_t cap, size_t *written, size_t *bit_len)
{
    const uint8_t *x;
    size_t         need;
    size_t         bits;

    if (public_key == NULL || out == NULL || written == NULL) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    /* Refuse a key we were not handed in the form the spec defines,
     * rather than deriving a credential from whatever bytes follow. */
    if (public_key[0] != 0x04U) {
        return ASYMCRED_ERR_INVALID_ARG;
    }

    x = &public_key[PKOC_X_OFFSET];

    switch (size) {
    case ASYMCRED_PKOC_CRED_256BIT:
        need = ASYMCRED_PKOC_CRED_256BIT_LEN;
        bits = 256U;
        break;
    case ASYMCRED_PKOC_CRED_75BIT:
        need = ASYMCRED_PKOC_CRED_75BIT_LEN;
        bits = 75U;
        break;
    case ASYMCRED_PKOC_CRED_64BIT:
        need = ASYMCRED_PKOC_CRED_64BIT_LEN;
        bits = 64U;
        break;
    default:
        return ASYMCRED_ERR_INVALID_ARG;
    }

    if (cap < need) {
        return ASYMCRED_ERR_BUFFER_TOO_SMALL;
    }

    if (size == ASYMCRED_PKOC_CRED_75BIT) {
        /* 75 bits is not a byte boundary: the low 9 bytes of X carry 72
         * of them, and the 3 remaining bits come from the byte above,
         * masked so the 5 bits that overflow the credential are dropped
         * rather than silently widening it to 80. */
        out[0] = (uint8_t)(x[PKOC_X_LEN - 10U] & 0x07U);
        (void)memcpy(&out[1], &x[PKOC_X_LEN - 9U], 9U);
    } else {
        (void)memcpy(out, &x[PKOC_X_LEN - need], need);
    }

    *written = need;

    if (bit_len != NULL) {
        *bit_len = bits;
    }

    return ASYMCRED_OK;
}
