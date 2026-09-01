// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef ASYMCRED_TYPES_H
#define ASYMCRED_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status / error codes returned from any AsymCred function that can fail.
 * ASYMCRED_OK is the only success value; everything else is an error.
 *
 * The numbering is stable — treat appending as the only permitted change,
 * the same rule OSDP-Embedded's osdp_status_t follows. */
typedef enum asymcred_status {
    ASYMCRED_OK = 0,

    /* Argument / contract violations from the caller. */
    ASYMCRED_ERR_INVALID_ARG,      /* NULL pointer, zero-length output, etc.  */
    ASYMCRED_ERR_BUFFER_TOO_SMALL, /* output buffer cannot hold the result    */
    ASYMCRED_ERR_INVALID_STATE,    /* call does not apply in the current state*/

    /* Wire-format / decoder errors. */
    ASYMCRED_ERR_TRUNCATED,        /* ran off the end of the buffer           */
    ASYMCRED_ERR_BAD_TLV,          /* malformed TLV (length overruns parent)  */
    ASYMCRED_ERR_MISSING_TLV,      /* a required tag was absent               */
    ASYMCRED_ERR_BAD_LENGTH,       /* a TLV was present but the wrong length  */

    /* Card / protocol errors. */
    ASYMCRED_ERR_CARD_STATUS,      /* card answered SW != 9000                */
    ASYMCRED_ERR_NO_APPLET,        /* SELECT was refused — applet not present */
    ASYMCRED_ERR_VERSION,          /* no protocol version in common with card */

    /* Cryptographic outcome. Distinct from an error in the plumbing: the
     * exchange completed and the card's signature did not verify against
     * the public key it presented. A reader MUST reject the credential. */
    ASYMCRED_ERR_BAD_SIGNATURE,

    /* Capability errors. */
    ASYMCRED_ERR_NOT_SUPPORTED     /* recognised but not implemented, or a
                                    * required crypto callback is NULL       */
} asymcred_status_t;

#ifdef __cplusplus
}
#endif

#endif /* ASYMCRED_TYPES_H */
