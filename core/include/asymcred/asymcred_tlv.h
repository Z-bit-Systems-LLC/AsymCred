// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef ASYMCRED_TLV_H
#define ASYMCRED_TLV_H

#include "asymcred/asymcred_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Simple tag-length-value codec for the PKOC dialect.
 *
 * PKOC 1.1 (section "TLV") uses a one-byte tag and a one-byte length.
 * Every value the spec defines is at most 65 bytes, so the multi-byte
 * BER length forms cannot arise and are deliberately not implemented —
 * a length byte >= 0x80 is a malformed record here, not a long form.
 *
 * Two rules from the spec drive this API:
 *   - "There is no strict ordering of TLVs within a message" — so the
 *     reader searches by tag rather than walking a fixed layout.
 *   - "any TLV command not recognized should be ignored" — so the
 *     iterator skips unknown tags instead of failing. */

typedef struct asymcred_tlv {
    uint8_t        tag;
    uint8_t        len;
    const uint8_t *value; /* points into the caller's buffer; not copied */
} asymcred_tlv_t;

/* Cursor over a TLV sequence. Initialise with asymcred_tlv_iter_init. */
typedef struct asymcred_tlv_iter {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
} asymcred_tlv_iter_t;

asymcred_status_t asymcred_tlv_iter_init(asymcred_tlv_iter_t *it,
                                         const uint8_t *buf, size_t len);

/* Advance to the next record.
 *
 * Returns ASYMCRED_OK and fills `*out` when one is available,
 * ASYMCRED_ERR_TRUNCATED when the sequence is exhausted cleanly, and
 * ASYMCRED_ERR_BAD_TLV when a record's length overruns the buffer or
 * uses a reserved long-form length byte. */
asymcred_status_t asymcred_tlv_iter_next(asymcred_tlv_iter_t *it,
                                         asymcred_tlv_t *out);

/* Find the first record carrying `tag`.
 *
 * Returns ASYMCRED_ERR_MISSING_TLV when the tag is absent, and
 * ASYMCRED_ERR_BAD_TLV when the sequence is malformed before the tag
 * is reached. Unknown tags encountered on the way are skipped. */
asymcred_status_t asymcred_tlv_find(const uint8_t *buf, size_t len,
                                    uint8_t tag, asymcred_tlv_t *out);

/* Append one record to `buf`. `*pos` is advanced past the bytes written.
 * `value` may be NULL only when `len` is 0. */
asymcred_status_t asymcred_tlv_put(uint8_t *buf, size_t cap, size_t *pos,
                                   uint8_t tag,
                                   const uint8_t *value, uint8_t len);

#ifdef __cplusplus
}
#endif

#endif /* ASYMCRED_TLV_H */
