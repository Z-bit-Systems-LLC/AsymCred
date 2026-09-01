// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef ASYMCRED_PKOC_H
#define ASYMCRED_PKOC_H

#include "asymcred/asymcred_crypto.h"
#include "asymcred/asymcred_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PKOC (Public Key Open Credential) reader-side transaction, per the
 * PSIA "PKOC NFC Card Specification" v1.1 (12/1/2023).
 *
 * This is the READER half. The card half - key generation, signing -
 * lives on the card and never exposes its private key.
 *
 * The library performs no I/O. It is a step machine: ask it for the
 * next C-APDU, put that on the wire yourself, feed the R-APDU back.
 * That keeps it usable from an interrupt-driven or RTOS-free NFC stack
 * and from a blocking PC/SC one alike. asymcred_pkoc_run() wraps the
 * loop for callers that do have a simple blocking transceive.
 *
 * Typical use, reader-side, feeding OSDP-Embedded:
 *
 *     asymcred_pkoc_t pkoc;
 *     asymcred_pkoc_begin(&pkoc, &cfg, &crypto);
 *
 *     while (asymcred_pkoc_pending(&pkoc)) {
 *         uint8_t c[ASYMCRED_PKOC_MAX_CAPDU], r[ASYMCRED_PKOC_MAX_RAPDU];
 *         size_t  clen, rlen;
 *
 *         asymcred_pkoc_next_apdu(&pkoc, c, sizeof c, &clen);
 *         pcd_transceive(c, clen, r, sizeof r, &rlen);
 *         if (asymcred_pkoc_feed(&pkoc, r, rlen) != ASYMCRED_OK) break;
 *     }
 *
 *     asymcred_pkoc_result_t res;
 *     if (asymcred_pkoc_result(&pkoc, &res) == ASYMCRED_OK) {
 *         uint8_t cred[10]; size_t clen, bits;
 *         asymcred_pkoc_credential(res.public_key,
 *                                  ASYMCRED_PKOC_CRED_75BIT,
 *                                  cred, sizeof cred, &clen, &bits);
 *     }
 *
 * Note the ordering the spec insists on: the reader verifies the
 * signature and only THEN derives a credential from the public key
 * (flow step 7). asymcred_pkoc_result() refuses to hand back a result
 * whose signature did not verify, so that ordering is not something a
 * caller can accidentally skip.
 */

/* ---- Wire constants ---------------------------------------------------- */

/* PKOC application identifier, spec "Variables". */
#define ASYMCRED_PKOC_AID_LEN 8U
extern const uint8_t asymcred_pkoc_aid[ASYMCRED_PKOC_AID_LEN];

/* TLV tags, spec "TLV". */
#define ASYMCRED_PKOC_TAG_PROTOCOL_VERSION 0x5CU
#define ASYMCRED_PKOC_TAG_TRANSACTION_ID   0x4CU
#define ASYMCRED_PKOC_TAG_READER_ID        0x4DU
#define ASYMCRED_PKOC_TAG_SIGNATURE        0x9EU
#define ASYMCRED_PKOC_TAG_PUBLIC_KEY       0x5AU

/* AUTHENTICATE, spec "Authentication Command". */
#define ASYMCRED_PKOC_CLA_AUTHENTICATE 0x80U
#define ASYMCRED_PKOC_INS_AUTHENTICATE 0x80U
#define ASYMCRED_PKOC_P1_AUTHENTICATE  0x00U
#define ASYMCRED_PKOC_P2_AUTHENTICATE  0x01U

/* Field lengths. The transaction identifier is 16 bytes in the
 * AUTHENTICATE command (which is why Lc is fixed at 0x38 = 56); the TLV
 * table separately allows 16..65, so a card must tolerate longer. This
 * implementation sends the 16 the command table specifies. */
#define ASYMCRED_PKOC_TXID_LEN        16U
#define ASYMCRED_PKOC_READER_ID_LEN   32U
#define ASYMCRED_PKOC_SITE_ID_LEN     16U
#define ASYMCRED_PKOC_LOCATION_ID_LEN 16U

/* Largest C-APDU this library emits: AUTHENTICATE, 5 + 56 + 1. */
#define ASYMCRED_PKOC_MAX_CAPDU 62U

/* Suggested R-APDU buffer. The AUTHENTICATE response is 2+65 + 2+64 + 2
 * = 135 bytes; the rest is headroom for a card that appends TLVs a
 * future version defines. */
#define ASYMCRED_PKOC_MAX_RAPDU 256U

/* Protocol versions as (major << 8) | minor. The spec's "Variables"
 * table and its worked example both use 0x0100. */
#define ASYMCRED_PKOC_VERSION(maj, min) ((uint16_t)(((maj) << 8) | (min)))
#define ASYMCRED_PKOC_VERSION_1_0       ASYMCRED_PKOC_VERSION(1, 0)
#define ASYMCRED_PKOC_VERSION_1_1       ASYMCRED_PKOC_VERSION(1, 1)

/* ---- Configuration ----------------------------------------------------- */

typedef struct asymcred_pkoc_config {
    /* 32-byte reader identifier sent in AUTHENTICATE: 16 bytes of site
     * key identifier followed by 16 bytes of reader location identifier
     * (spec "Variables"). Compose it with
     * asymcred_pkoc_make_reader_id() if you hold the halves separately. */
    uint8_t reader_id[ASYMCRED_PKOC_READER_ID_LEN];

    /* Versions this reader understands, most-preferred first. The card
     * lists what it supports in its SELECT response (most recent first);
     * the transaction uses the first entry here that the card also
     * offers, and fails ASYMCRED_ERR_VERSION when there is no overlap.
     *
     * Caller-owned storage that must outlive the transaction. NULL with
     * a count of 0 accepts whatever version the card lists first. */
    const uint16_t *supported_versions;
    size_t          supported_version_count;

    /* When true (the normal setting for an access decision), the card's
     * signature is verified over the transaction identifier and a
     * failure aborts the transaction.
     *
     * Set false ONLY for enrolment or bench diagnostics, where reading
     * the public key off a card is the whole point. An unverified public
     * key proves nothing: it is a value the card claimed, replayable by
     * anyone who has seen one exchange. Never gate access on it. */
    bool require_signature;
} asymcred_pkoc_config_t;

/* ---- Transaction state ------------------------------------------------- */

typedef enum asymcred_pkoc_state {
    ASYMCRED_PKOC_STATE_SELECT,   /* next APDU is SELECT               */
    ASYMCRED_PKOC_STATE_AUTH,     /* next APDU is AUTHENTICATE         */
    ASYMCRED_PKOC_STATE_COMPLETE, /* result is available               */
    ASYMCRED_PKOC_STATE_FAILED    /* aborted; see asymcred_pkoc_error  */
} asymcred_pkoc_state_t;

/* Treat as opaque - the layout is exposed only so the caller can place
 * the instance in its own storage. No dynamic allocation anywhere. */
typedef struct asymcred_pkoc {
    asymcred_pkoc_config_t config;
    asymcred_crypto_t      crypto;

    asymcred_pkoc_state_t  state;
    asymcred_status_t      error;    /* why we entered _FAILED         */
    uint16_t               card_sw;  /* last status word from the card */

    uint16_t               version;  /* negotiated protocol version    */
    uint8_t                txid[ASYMCRED_PKOC_TXID_LEN];

    uint8_t                public_key[ASYMCRED_P256_PUBKEY_LEN];
    uint8_t                signature[ASYMCRED_P256_SIG_LEN];
    bool                   have_signature;
    bool                   signature_verified;
} asymcred_pkoc_t;

typedef struct asymcred_pkoc_result {
    uint16_t version;
    uint8_t  public_key[ASYMCRED_P256_PUBKEY_LEN];
    uint8_t  transaction_id[ASYMCRED_PKOC_TXID_LEN];
    uint8_t  signature[ASYMCRED_P256_SIG_LEN];
    bool     have_signature;
    bool     signature_verified;
} asymcred_pkoc_result_t;

/* ---- Transaction driving ----------------------------------------------- */

/* Start a transaction, drawing a fresh transaction identifier from
 * crypto->rand_bytes. `config` and `crypto` are copied into `pkoc`
 * (the version list is copied by pointer - see the config comment). */
asymcred_status_t asymcred_pkoc_begin(asymcred_pkoc_t *pkoc,
                                      const asymcred_pkoc_config_t *config,
                                      const asymcred_crypto_t *crypto);

/* As above, with a caller-supplied transaction identifier. For replaying
 * spec test vectors and for readers whose nonce comes from elsewhere.
 * In production the value MUST be unpredictable and never reused - it is
 * the only thing making the card's signature fresh. */
asymcred_status_t asymcred_pkoc_begin_with_transaction_id(
    asymcred_pkoc_t *pkoc,
    const asymcred_pkoc_config_t *config,
    const asymcred_crypto_t *crypto,
    const uint8_t txid[ASYMCRED_PKOC_TXID_LEN]);

/* True while the transaction still has an APDU to exchange. */
bool asymcred_pkoc_pending(const asymcred_pkoc_t *pkoc);

asymcred_pkoc_state_t asymcred_pkoc_state(const asymcred_pkoc_t *pkoc);

/* Reason the transaction entered _FAILED, or ASYMCRED_OK if it has not. */
asymcred_status_t asymcred_pkoc_error(const asymcred_pkoc_t *pkoc);

/* Status word from the card's most recent response. Meaningful after a
 * feed that returned ASYMCRED_ERR_CARD_STATUS or ASYMCRED_ERR_NO_APPLET;
 * the PKOC status codes are named in asymcred_apdu.h. */
uint16_t asymcred_pkoc_card_sw(const asymcred_pkoc_t *pkoc);

/* Write the next C-APDU for the current state into `buf`. Does not
 * change state - the transaction advances on feed, so a caller whose
 * transceive failed can simply ask again and retry. */
asymcred_status_t asymcred_pkoc_next_apdu(asymcred_pkoc_t *pkoc,
                                          uint8_t *buf, size_t cap,
                                          size_t *written);

/* Feed the card's R-APDU (body AND the two status-word bytes).
 *
 * Returns ASYMCRED_OK when the response was accepted and the machine
 * advanced. Any other return also moves the machine to _FAILED and is
 * recorded in asymcred_pkoc_error(). */
asymcred_status_t asymcred_pkoc_feed(asymcred_pkoc_t *pkoc,
                                     const uint8_t *rapdu, size_t len);

/* Copy out the completed transaction.
 *
 * Returns ASYMCRED_ERR_INVALID_STATE unless the state is _COMPLETE, so
 * a caller cannot read a public key out of a transaction that failed or
 * whose signature did not verify. */
asymcred_status_t asymcred_pkoc_result(const asymcred_pkoc_t *pkoc,
                                       asymcred_pkoc_result_t *out);

/* Drive the whole exchange through a blocking transceive callback.
 *
 * `transceive` must place the card's full R-APDU (including SW) in
 * `rsp` and set `*rsp_len`. Returning anything but ASYMCRED_OK aborts
 * the transaction. Convenience only - everything it does is available
 * through the step API above. */
typedef asymcred_status_t (*asymcred_pkoc_transceive_fn)(
    void          *user,
    const uint8_t *cmd, size_t cmd_len,
    uint8_t       *rsp, size_t rsp_cap, size_t *rsp_len);

asymcred_status_t asymcred_pkoc_run(asymcred_pkoc_t *pkoc,
                                    asymcred_pkoc_transceive_fn transceive,
                                    void *user,
                                    asymcred_pkoc_result_t *out);

/* ---- Helpers ----------------------------------------------------------- */

/* Compose the 32-byte reader identifier from its two 16-byte halves. */
asymcred_status_t asymcred_pkoc_make_reader_id(
    const uint8_t site_id    [ASYMCRED_PKOC_SITE_ID_LEN],
    const uint8_t location_id[ASYMCRED_PKOC_LOCATION_ID_LEN],
    uint8_t out[ASYMCRED_PKOC_READER_ID_LEN]);

/* ---- Credential derivation --------------------------------------------- */

/* Credential widths the spec defines (section "PKOC- Credential Creation
 * and Provisioning", item 3). All are taken from the X component of the
 * public key - the low-order bits for the truncated forms. */
typedef enum asymcred_pkoc_cred_size {
    ASYMCRED_PKOC_CRED_256BIT, /* full X; for panels that can carry it  */
    ASYMCRED_PKOC_CRED_75BIT,  /* recommended for legacy panels         */
    ASYMCRED_PKOC_CRED_64BIT   /* minimum for legacy panels             */
} asymcred_pkoc_cred_size_t;

/* Bytes needed to hold each width (75 bits occupies 10 bytes). */
#define ASYMCRED_PKOC_CRED_256BIT_LEN 32U
#define ASYMCRED_PKOC_CRED_75BIT_LEN  10U
#define ASYMCRED_PKOC_CRED_64BIT_LEN   8U
#define ASYMCRED_PKOC_CRED_MAX_LEN    ASYMCRED_PKOC_CRED_256BIT_LEN

/* Derive the panel-facing credential from a 65-byte public key.
 *
 * The result is right-aligned and big-endian, so it drops straight into
 * an OSDP osdp_RAW payload: `*bit_len` is the bit count for that reply
 * and the unused high bits of the first byte are zero. For the 75-bit
 * form that means 10 bytes whose top 5 bits are clear.
 *
 * `bit_len` may be NULL if the caller does not need it. */
asymcred_status_t asymcred_pkoc_credential(
    const uint8_t public_key[ASYMCRED_P256_PUBKEY_LEN],
    asymcred_pkoc_cred_size_t size,
    uint8_t *out, size_t cap, size_t *written, size_t *bit_len);

#ifdef __cplusplus
}
#endif

#endif /* ASYMCRED_PKOC_H */
