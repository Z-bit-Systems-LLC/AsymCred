# AsymCred

Embedded C11 library implementing open credential standards for access control readers, starting with PKOC.

[![License](https://img.shields.io/badge/license-GPL--3.0--or--later%20%7C%20Commercial-blue.svg)](LICENSE.md)
[![Standard](https://img.shields.io/badge/C-C11%20freestanding-blue.svg)](#supported-platforms)
[![Spec](https://img.shields.io/badge/PKOC-1.1%20(PSIA)-green.svg)](https://psialliance.org/)

## Overview

Access control readers have historically presented credentials the panel
must simply trust: a card number, transmitted in the clear, cloneable by
anyone who can read it once. Public-key credentials change that. The card
holds a private key that never leaves its secure element and proves
possession by signing a challenge the reader supplies. Cloning requires
the key, not the transmitted bits.

AsymCred implements the reader side of that exchange. It is the credential
layer that sits beneath a protocol stack:
[OSDP-Embedded](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded) carries
a credential to the panel; AsymCred is what produces one.

**Key features**

- **PKOC 1.1 complete, reader side** — SELECT, protocol-version
  negotiation, AUTHENTICATE, signature verification, credential
  derivation.
- **No I/O, no allocation, no OS.** Freestanding C11. All buffers
  caller-owned, every function reentrant. Nothing here calls `malloc`,
  touches a global, or blocks.
- **Bring your own crypto.** SHA-256, ECDSA P-256 verification and the
  CSPRNG are supplied through a small HAL, so a device uses the hardware
  accelerator and entropy source it already has.
- **A step machine, not a driver.** Ask for the next APDU, put it on the
  wire yourself, feed the response back — equally usable from an
  interrupt-driven NFC stack or a blocking PC/SC one.
- **Both ends of the protocol.** [`card/`](card/) holds the JavaCard
  applet that runs on the card itself.

**Standards context**

PKOC — Public Key Open Credential — is published by the
[PSIA](https://psialliance.org/) (Physical Security Interoperability
Alliance). This implementation follows the *PKOC NFC Card Specification
v1.1* (Rev0, 12/1/2023), using ECC P-256 over ISO 14443-A. The spec's own
worked example is reproduced byte for byte in the test suite.

## Supported Platforms

| Requirement | Detail |
|---|---|
| Language | C11 (`-std=c11`, no compiler extensions) |
| Standard library | Freestanding headers only — `stdint.h`, `stddef.h`, `stdbool.h`, `string.h` |
| Memory | No dynamic allocation. Largest object is ~200 bytes of caller-provided transaction state |
| OS | None required. No threads, no file I/O, no sockets, no timers |
| Toolchains | GCC, Clang, MSVC, ARM GCC, RISC-V GCC, xtensa-esp32 |
| Build | CMake 3.16+ |

Verified on MSVC 19.37 (x64). The library is written to the strict GCC
warning set the build declares (`-Wconversion`, `-Wsign-conversion`,
`-Wcast-qual` and friends), but see [Testing &
Development](#testing--development) for what has actually been exercised.

## Installation

### CMake FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(asymcred
    GIT_REPOSITORY https://github.com/Z-bit-Systems-LLC/AsymCred.git
    GIT_TAG        main)
set(ASYMCRED_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(asymcred)

target_link_libraries(my_reader PRIVATE asymcred::pkoc)
```

`asymcred::pkoc` pulls in `asymcred::core` transitively.

### Subdirectory

```cmake
add_subdirectory(external/AsymCred)
target_link_libraries(my_reader PRIVATE asymcred::pkoc)
```

### Building standalone

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

| Option | Default | Effect |
|---|---|---|
| `ASYMCRED_BUILD_TESTS` | `ON` | Build and register the unit tests |
| `ASYMCRED_SANITIZE` | `OFF` | AddressSanitizer, plus UBSan on GCC/Clang |

## Quick Start

Read a credential from a card and get the bits to send to the panel:

```c
#include "asymcred/asymcred_pkoc.h"

asymcred_pkoc_config_t cfg = { .require_signature = true };
asymcred_pkoc_make_reader_id(site_id, location_id, cfg.reader_id);

asymcred_pkoc_t        pkoc;
asymcred_pkoc_result_t result;

asymcred_pkoc_begin(&pkoc, &cfg, &crypto);

if (asymcred_pkoc_run(&pkoc, my_transceive, &pcd, &result) == ASYMCRED_OK) {
    uint8_t cred[ASYMCRED_PKOC_CRED_75BIT_LEN];
    size_t  len, bits;

    asymcred_pkoc_credential(result.public_key, ASYMCRED_PKOC_CRED_75BIT,
                             cred, sizeof cred, &len, &bits);
    /* cred/bits are ready for an osdp_RAW reply */
}
```

`asymcred_pkoc_run()` returns non-`OK` if the card is absent, the applet
is missing, or the signature fails — a successful return means the card
proved possession of its private key.

## Common Scenarios

### Presenting a credential at the door

The full path from card tap to panel, wiring AsymCred to OSDP-Embedded:

```c
static void on_card_present(pcd_t *pcd)
{
    asymcred_pkoc_config_t cfg = { .require_signature = true };
    asymcred_pkoc_t        pkoc;
    asymcred_pkoc_result_t result;
    asymcred_status_t      st;

    memcpy(cfg.reader_id, g_reader_id, sizeof cfg.reader_id);

    st = asymcred_pkoc_begin(&pkoc, &cfg, &g_crypto);
    if (st != ASYMCRED_OK) {
        return;
    }

    st = asymcred_pkoc_run(&pkoc, pcd_transceive, pcd, &result);
    if (st != ASYMCRED_OK) {
        log_denied(st, asymcred_pkoc_card_sw(&pkoc));
        return;
    }

    uint8_t cred[ASYMCRED_PKOC_CRED_75BIT_LEN];
    size_t  len, bits;

    asymcred_pkoc_credential(result.public_key, ASYMCRED_PKOC_CRED_75BIT,
                             cred, sizeof cred, &len, &bits);

    /* Encode an osdp_RAW reply and queue it for the next osdp_POLL. */
    osdp_raw_t raw = {
        .reader_no    = 0,
        .format_code  = OSDP_RAW_FORMAT_RAW,
        .bit_count    = (uint16_t)bits,
        .bit_data     = cred,
        .bit_data_len = len,
    };

    uint8_t payload[OSDP_RAW_HEADER_BYTES + ASYMCRED_PKOC_CRED_75BIT_LEN];
    size_t  payload_len;

    if (osdp_raw_build(&raw, payload, sizeof payload, &payload_len) == OSDP_OK) {
        osdp_pd_enqueue_event(&g_pd, OSDP_REPLY_RAW, payload, payload_len);
    }
}
```

### Enrolling a card

Enrolment reads the public key to register it with the access control
system. There is no access decision here, so a signature is not required:

```c
asymcred_pkoc_config_t cfg = { .require_signature = false };
asymcred_pkoc_t        pkoc;
asymcred_pkoc_result_t result;

asymcred_pkoc_begin(&pkoc, &cfg, &crypto);

if (asymcred_pkoc_run(&pkoc, transceive, &pcd, &result) == ASYMCRED_OK) {
    register_public_key(result.public_key);   /* 65 bytes, 0x04 || X || Y */
}
```

`require_signature = false` is for enrolment and bench diagnostics only.
The result reports `signature_verified == false`, and an unverified public
key is a value the card merely claimed — replayable by anyone who has
observed one exchange. Never gate access on it.

### Telling a PKOC card from any other card

A reader polling mixed credential types needs to distinguish "not a PKOC
card" from "a PKOC card that failed":

```c
st = asymcred_pkoc_run(&pkoc, transceive, &pcd, &result);

switch (st) {
case ASYMCRED_OK:
    grant_or_deny(&result);
    break;
case ASYMCRED_ERR_NO_APPLET:
    try_next_credential_type(&pcd);       /* SELECT refused; not PKOC  */
    break;
case ASYMCRED_ERR_BAD_SIGNATURE:
    alarm_cloned_credential();            /* PKOC card, invalid proof  */
    break;
default:
    log_error(st, asymcred_pkoc_card_sw(&pkoc));
    break;
}
```

### Matching the panel's credential width

Legacy panels cannot carry 256 bits. The spec defines two truncated forms,
both taken from the low-order end of the key's X component:

```c
uint8_t cred[ASYMCRED_PKOC_CRED_MAX_LEN];
size_t  len, bits;

/* 75-bit: recommended for legacy panels */
asymcred_pkoc_credential(result.public_key, ASYMCRED_PKOC_CRED_75BIT,
                         cred, sizeof cred, &len, &bits);   /* 10 bytes, 75 bits */

/* 64-bit: the stated minimum */
asymcred_pkoc_credential(result.public_key, ASYMCRED_PKOC_CRED_64BIT,
                         cred, sizeof cred, &len, &bits);   /*  8 bytes, 64 bits */
```

Output is right-aligned big-endian with unused leading bits cleared, and
the bit count comes back alongside — the two things an `osdp_RAW` payload
needs. Because the truncated forms are suffixes of the full credential,
widening a site later does not renumber existing cards.

## Core Concepts

### The exchange

```
Reader (this library)                                Card (card/)
  |                                                       |
  |-- SELECT (AID A000000898000001) --------------------->|
  |<-- 5C <supported protocol versions>          SW 9000 --|
  |                                                       |
  |   negotiate a version both sides understand           |
  |   draw a 16-byte transaction ID from the CSPRNG       |
  |                                                       |
  |-- AUTHENTICATE (5C version, 4C txid, 4D reader id) -->|
  |                                   sign(txid) on-card  |
  |<-- 5A <public key 65>  9E <signature 64>     SW 9000 --|
  |                                                       |
  |   verify ECDSA-P256-SHA256 over the transaction ID    |
  |   derive the credential from the X component          |
  v
osdp_RAW to the panel
```

The card signs the transaction identifier and nothing else — not the
reader identifier, not the command data. That is confirmed against the
specification's own worked example rather than inferred from its prose.

### The transaction identifier is the security boundary

It is the only thing making the card's signature fresh. A counter, a
timestamp, or a PRNG seeded from a fixed value makes a captured response
replayable and defeats the protocol. `rand_bytes` must be a
cryptographically secure generator.

### An unverified key is unreachable

`asymcred_pkoc_result()` returns `ASYMCRED_ERR_INVALID_STATE` unless the
transaction reached `_COMPLETE`, and a verification failure routes to
`_FAILED` instead. A caller that ignores every return value still cannot
obtain a public key that did not verify. The spec's ordering — verify,
*then* derive a credential — is enforced by the API rather than left to
convention.

## Advanced Usage

### Binding the crypto HAL

The library ships no cryptography. Supply three callbacks:

```c
static asymcred_status_t hal_sha256(void *user, const uint8_t *msg,
                                    size_t len, uint8_t out[32])
{
    (void)user;
    return mbedtls_sha256(msg, len, out, 0) == 0
        ? ASYMCRED_OK : ASYMCRED_ERR_NOT_SUPPORTED;
}

static asymcred_status_t hal_verify(void *user, const uint8_t pub[65],
                                    const uint8_t digest[32],
                                    const uint8_t sig[64])
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi       r, s;
    int               rc;

    (void)user;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) rc = mbedtls_ecp_point_read_binary(&grp, &Q, pub, 65);
    if (rc == 0) rc = mbedtls_mpi_read_binary(&r, sig, 32);
    if (rc == 0) rc = mbedtls_mpi_read_binary(&s, sig + 32, 32);
    if (rc == 0) rc = mbedtls_ecdsa_verify(&grp, digest, 32, &Q, &r, &s);

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);

    return (rc == 0) ? ASYMCRED_OK : ASYMCRED_ERR_BAD_SIGNATURE;
}

static asymcred_status_t hal_rand(void *user, uint8_t *out, size_t len)
{
    (void)user;
    esp_fill_random(out, len);
    return ASYMCRED_OK;
}

static const asymcred_crypto_t g_crypto = {
    .sha256            = hal_sha256,
    .ecdsa_p256_verify = hal_verify,
    .rand_bytes        = hal_rand,
    .user              = NULL,
};
```

Note the shapes: verification receives a **digest**, not a message, and a
**raw 64-byte R‖S** signature, not DER. On an MCU with an ECC
accelerator, bind these to the hardware instead — the interface is the
same.

`asymcred_pkoc_begin()` returns `ASYMCRED_ERR_NOT_SUPPORTED` if
`require_signature` is set and either crypto callback is `NULL`, so a
missing primitive fails at setup rather than silently skipping
verification.

### Driving the transaction without blocking

`asymcred_pkoc_run()` assumes a blocking transceive. Where that does not
fit — an interrupt-driven NFC stack, a cooperative scheduler — drive the
steps directly:

```c
while (asymcred_pkoc_pending(&pkoc)) {
    uint8_t cmd[ASYMCRED_PKOC_MAX_CAPDU];
    uint8_t rsp[ASYMCRED_PKOC_MAX_RAPDU];
    size_t  cmd_len, rsp_len;

    if (asymcred_pkoc_next_apdu(&pkoc, cmd, sizeof cmd, &cmd_len) != ASYMCRED_OK) {
        break;
    }

    if (pcd_exchange(cmd, cmd_len, rsp, sizeof rsp, &rsp_len) != 0) {
        break;                        /* transport failure — retry or abort */
    }

    if (asymcred_pkoc_feed(&pkoc, rsp, rsp_len) != ASYMCRED_OK) {
        break;                        /* reason is in asymcred_pkoc_error() */
    }
}
```

`next_apdu()` does not mutate state — the transaction advances only on
`feed()` — so a caller whose transceive failed can simply ask again and
retry the same step.

### Error handling

Every fallible function returns `asymcred_status_t`. The ones a reader
application will actually branch on:

| Status | Meaning | Typical response |
|---|---|---|
| `ASYMCRED_OK` | Success | Proceed |
| `ASYMCRED_ERR_NO_APPLET` | SELECT refused — not a PKOC card | Try another credential type |
| `ASYMCRED_ERR_BAD_SIGNATURE` | Card's proof did not verify | Deny; consider alarming |
| `ASYMCRED_ERR_CARD_STATUS` | Card returned a non-9000 status word | Inspect `asymcred_pkoc_card_sw()` |
| `ASYMCRED_ERR_VERSION` | No protocol version in common | Log; card is too new or too old |
| `ASYMCRED_ERR_MISSING_TLV` | A required field was absent | Malformed or non-conforming card |
| `ASYMCRED_ERR_BAD_TLV` / `_BAD_LENGTH` | Malformed response | Malformed or non-conforming card |
| `ASYMCRED_ERR_INVALID_STATE` | Called out of sequence | Programming error |

After a failure, `asymcred_pkoc_error()` returns the status that stopped
the transaction and `asymcred_pkoc_card_sw()` the card's own last status
word, so a log line can carry both the library's diagnosis and the card's.

### Pinning a protocol version

By default the library accepts the card's most-recent advertised version.
To pin one deliberately:

```c
static const uint16_t supported[] = {
    ASYMCRED_PKOC_VERSION_1_0,
};

cfg.supported_versions      = supported;
cfg.supported_version_count = 1;
```

The list is walked in the caller's preference order, taking the first
entry the card also offers; with no overlap the transaction fails
`ASYMCRED_ERR_VERSION`. Storage is caller-owned and must outlive the
transaction.

## Testing & Development

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

45 tests across 4 suites ([Unity](https://github.com/ThrowTheSwitch/Unity),
vendored). The PKOC 1.1 specification's worked example is reproduced byte
for byte — both C-APDUs, both R-APDUs, and all three derived credential
widths.

Two limitations worth stating plainly:

- **No verification maths is tested, because the library contains none.**
  That is the HAL-only design working as intended. The suite binds a real
  SHA-256 (with known-answer tests) and a scriptable ECDSA stub that
  records its arguments, which pins the state machine's contract —
  including the exact digest handed to verification — but proves nothing
  about any particular P-256 implementation. The spec's signature was
  verified independently with openssl to confirm the vector itself.
- **Only MSVC has compiled this.** The build declares the strict GCC
  warning set, but no GCC or Clang toolchain has exercised it yet.

The card-side applet has its own toolchain and its own 8 jCardSim tests —
see [`card/README.md`](card/README.md).

## Documentation

- [`card/README.md`](card/README.md) — the JavaCard applet: build,
  jCardSim tests, loading onto physical cards
- [`CLAUDE.md`](CLAUDE.md) — architectural decisions, coding rules, and
  the specification details pinned down during implementation
- [`LICENSE.md`](LICENSE.md) — the mixed-licensing rationale

Specification documents are not redistributed; `docs/spec/` is
git-ignored. PKOC specifications are available from the
[PSIA](https://psialliance.org/).

## Roadmap

AsymCred is the first of a planned suite of open credential libraries for
embedded readers. Rather than one library per vendor, one library per
published standard, sharing the same TLV, APDU and crypto-HAL foundation.

| Standard | Cryptography | Status |
|---|---|---|
| **PKOC 1.1** (PSIA) | ECC P-256, public key as credential | **Implemented** — reader and card |
| **LEAF** | AES-128 over MIFARE DESFire EV2/EV3 | Planned |
| **Aliro** (CSA) | ECC P-256, NFC + BLE + UWB | Planned |

PKOC and Aliro are public-key standards; LEAF is symmetric. What they
share is being *open* — published specifications any manufacturer can
implement — and needing the same embedded foundation underneath: TLV, APDU
framing, a crypto HAL, and no assumptions about an operating system.

Also under consideration for the PKOC line: the OSDP transport binding
(`pkoc-osdp-acu`), the ECDHE-based PKOC v2 direction, and BLE transport.

## Contributing

We welcome contributions! Please:

1. Submit pull requests against the `main` branch
2. Follow existing code style and conventions — see
   [`CLAUDE.md`](CLAUDE.md) for the coding rules this project holds to
   (freestanding C11, no allocation, SPDX headers, caller-owned buffers)
3. Include tests for new features — a round-trip test and at least one
   negative test per codec
4. Update documentation as needed

Contributions are licensed under the license of the directory they touch:
Apache-2.0 for `card/`, GPL-3.0-or-later for everything else. See
[`LICENSE.md`](LICENSE.md).

For collaboration inquiries or questions, contact us through
[Z-bit Systems, LLC](https://z-bitco.com).

## License

This project uses two licenses, by design:

| Path | Runs on | License |
|---|---|---|
| `card/` | the card | Apache-2.0 |
| `core/`, `pkoc/`, `tests/` | the reader | GPL-3.0-or-later **or** commercial |

The applet is permissive so anyone can adopt it — PKOC is an open
standard, and the card side should not require a licensing conversation.
The commercial option applies to the reader library.

The two never link: different devices, no shared binary, communicating
only over the APDU wire protocol. See [LICENSE.md](LICENSE.md) for the
full reasoning and [LICENSING](LICENSING) for commercial inquiries.

## Related Projects

- [OSDP-Embedded](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded) —
  SIA OSDP v2.2.2 for embedded devices; the protocol stack this library
  feeds
- [OSDP.Net](https://github.com/Z-bit-Systems-LLC/OSDP.Net) — .NET
  implementation of OSDP
- [Cred-Bench](https://github.com/Z-bit-Systems-LLC/Cred-Bench) —
  cross-platform diagnostic tool for identifying and examining credential
  technologies

## Support

For questions, issues, or feature requests:
- Open an issue on [GitHub Issues](https://github.com/Z-bit-Systems-LLC/AsymCred/issues)
- Contact [Z-bit Systems, LLC](https://z-bitco.com)

---

**About Z-bit Systems, LLC**

Z-bit Systems specializes in access control systems, physical security
integration, and enterprise security software solutions. We provide
commercial support, custom development, and consulting services. Learn
more at [z-bitco.com](https://z-bitco.com).
