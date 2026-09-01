// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef ASYMCRED_APDU_H
#define ASYMCRED_APDU_H

#include "asymcred/asymcred_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ISO 7816-4 short APDU helpers.
 *
 * PKOC uses exactly two commands and both are case 4 short (command data
 * present, response data expected), so this is deliberately narrow: build
 * a case-4 short C-APDU, split an R-APDU into body and status word. No
 * extended length, no chaining, no GET RESPONSE — a PKOC AUTHENTICATE
 * response is 133 bytes and fits a single short R-APDU.
 *
 * A contactless stack that returns 61xx / 6Cxx is doing ISO-DEP framing
 * this layer does not model; handle that in the PCD driver and hand this
 * library the reassembled response. */

/* Status words named by PKOC 1.1 "Status Codes". They are the ISO 7816-4
 * values, listed here so a caller can report the card's own diagnosis. */
#define ASYMCRED_SW_SUCCESS          0x9000U /* Success                    */
#define ASYMCRED_SW_WRONG_LENGTH     0x6700U /* Wrong length in Lc         */
#define ASYMCRED_SW_BAD_VERSION      0x6985U /* Unsupported protocol ver.  */
#define ASYMCRED_SW_WRONG_P1P2       0x6B00U /* Incorrect P1 or P2         */
#define ASYMCRED_SW_INVALID_INS      0x6D00U /* Invalid INS                */
#define ASYMCRED_SW_INVALID_CLA      0x6E00U /* Invalid CLA                */
#define ASYMCRED_SW_GENERAL_ERROR    0x6F00U /* General error              */

/* Build a case-4 short C-APDU: CLA INS P1 P2 Lc <data> Le.
 *
 * `data_len` must be 1..255 — PKOC has no case-2 (no command data)
 * exchange, so a zero-length body is rejected as a caller error rather
 * than silently emitting a case-2 APDU with different framing. */
asymcred_status_t asymcred_apdu_build(uint8_t cla, uint8_t ins,
                                      uint8_t p1, uint8_t p2,
                                      const uint8_t *data, size_t data_len,
                                      uint8_t le,
                                      uint8_t *buf, size_t cap,
                                      size_t *written);

/* Split an R-APDU into its body and status word.
 *
 * `rapdu` must be at least the two SW bytes. On success `*body` points
 * into `rapdu` (nothing is copied), `*body_len` is the length before the
 * status word, and `*sw` is the big-endian SW1||SW2.
 *
 * A non-9000 status word is NOT an error here — the caller decides what
 * a given status means in context. */
asymcred_status_t asymcred_apdu_split(const uint8_t *rapdu, size_t len,
                                      const uint8_t **body, size_t *body_len,
                                      uint16_t *sw);

#ifdef __cplusplus
}
#endif

#endif /* ASYMCRED_APDU_H */
