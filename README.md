# AsymCred

Asymmetric credential support for embedded access control readers, built
to sit alongside [OSDP-Embedded](../OSDP-Embedded).

OSDP-Embedded carries a credential to the panel. AsymCred is what produces
one — it runs the card transaction at the reader, verifies the card's
signature, and derives the value the panel actually receives.

Written in freestanding C11: no malloc, no globals, no OS calls, no I/O.
All buffers caller-owned.

## Status

**Iteration 1.** PKOC 1.1 (PSIA, NFC card) reader side, complete:

- **TLV codec** for the PKOC dialect — one-byte tag, one-byte length,
  order-independent lookup, unknown tags skipped for forward
  compatibility, malformed records rejected rather than misread.
- **ISO 7816-4 case-4 short APDU** build and split.
- **Transaction state machine** — SELECT, protocol-version negotiation
  across the card's advertised list, AUTHENTICATE with a fresh
  transaction identifier, signature verification, result.
- **Credential derivation** — 256-bit, 75-bit, and 64-bit forms from the
  X component, right-aligned and bit-counted so the result drops straight
  into an `osdp_RAW` payload.
- **45 tests** across 4 suites, including the spec's worked example
  reproduced byte for byte.

The card side is here too: [`card/`](card/) holds the PKOC JavaCard
applet — on-card P-256 key generation and the signing half of the
exchange, with 8 jCardSim tests. Separate toolchain (Java, Ant, JDK 8),
not part of the CMake build. See [`card/README.md`](card/README.md).

So both ends of the protocol live in one repository: `card/` signs the
transaction identifier, `pkoc/` verifies it and derives the credential.

## What PKOC is

The card generates a P-256 key pair in a secure element at provisioning.
The private key never leaves the card. The public key *is* the credential:
it is registered with the access control system at enrolment, and at the
door the card proves it holds the matching private key by signing a nonce
the reader supplies.

That is the whole point of the asymmetric approach — a reader holds no
secret worth stealing, and cloning a card requires the private key rather
than the bits the card transmits.

## The exchange

```
Reader                                                    Card
  |                                                         |
  |-- SELECT (AID A000000898000001) ----------------------->|
  |<-- 5C <supported protocol versions>            SW 9000 --|
  |                                                         |
  |   pick a version both sides understand                  |
  |   draw a 16-byte transaction identifier from the CSPRNG  |
  |                                                         |
  |-- AUTHENTICATE (5C version, 4C txid, 4D reader id) ---->|
  |                                     sign(txid) on-card  |
  |<-- 5A <public key 65>  9E <signature 64>       SW 9000 --|
  |                                                         |
  |   verify ECDSA-P256-SHA256 over the transaction id      |
  |   derive the credential from the X component            |
  v
osdp_RAW to the panel
```

The card signs the transaction identifier and nothing else — verified
against the spec's own worked example rather than inferred.

## Usage

The library performs no I/O. Ask it for the next APDU, put that on the
wire yourself, feed the response back:

```c
#include "asymcred/asymcred_pkoc.h"

asymcred_pkoc_config_t cfg = { .require_signature = true };
asymcred_pkoc_make_reader_id(site_id, location_id, cfg.reader_id);

asymcred_pkoc_t pkoc;
asymcred_pkoc_begin(&pkoc, &cfg, &crypto);

while (asymcred_pkoc_pending(&pkoc)) {
    uint8_t c[ASYMCRED_PKOC_MAX_CAPDU], r[ASYMCRED_PKOC_MAX_RAPDU];
    size_t  clen, rlen;

    asymcred_pkoc_next_apdu(&pkoc, c, sizeof c, &clen);
    pcd_transceive(c, clen, r, sizeof r, &rlen);
    if (asymcred_pkoc_feed(&pkoc, r, rlen) != ASYMCRED_OK) break;
}

asymcred_pkoc_result_t res;
if (asymcred_pkoc_result(&pkoc, &res) == ASYMCRED_OK) {
    uint8_t cred[ASYMCRED_PKOC_CRED_75BIT_LEN];
    size_t  len, bits;

    asymcred_pkoc_credential(res.public_key, ASYMCRED_PKOC_CRED_75BIT,
                             cred, sizeof cred, &len, &bits);
    /* cred/bits go out as osdp_RAW */
}
```

`asymcred_pkoc_run()` wraps that loop for callers with a blocking
transceive.

`asymcred_pkoc_result()` refuses to return anything unless the
transaction completed *and* the signature verified — an unverified public
key is not reachable through the API.

## Crypto

The library vendors no crypto. Supply three primitives:

```c
asymcred_crypto_t crypto = {
    .sha256            = my_sha256,
    .ecdsa_p256_verify = my_p256_verify,   /* digest, raw R||S */
    .rand_bytes        = my_csprng,
    .user              = &my_context,
};
```

Bind them to a hardware PKA and TRNG on an MCU, or micro-ecc / tinycrypt
/ mbedTLS / BearSSL in software. This mirrors OSDP-Embedded's
`osdp_sc_crypto_t` and exists for the same reason: a production device
should use the accelerator and entropy source it already has.

`rand_bytes` must be cryptographically secure. The transaction identifier
is the only thing making the card's signature fresh; a counter or a
timestamp makes a captured response replayable.

## Credential formats

All three are taken from the X component of the public key, per the spec:

| Form     | Bits | Bytes | Use                              |
| -------- | ---- | ----- | -------------------------------- |
| Full     | 256  | 32    | Panels with bi-directional comms |
| Truncated| 75   | 10    | Recommended for legacy panels    |
| Truncated| 64   | 8     | Minimum for legacy panels        |

Output is right-aligned big-endian with unused high bits cleared, and the
bit count is returned alongside — the two things an `osdp_RAW` reply
needs.

## Building

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

`ASYMCRED_BUILD_TESTS` (default ON) and `ASYMCRED_SANITIZE` (default OFF)
are the available options.

### Targets

| Target           | Contents                               |
| ---------------- | -------------------------------------- |
| `asymcred::core` | TLV codec, APDU helpers                |
| `asymcred::pkoc` | PKOC state machine, credential derive  |

A reader that only derives credentials from an already-read key links
`pkoc` without pulling in the state machine, thanks to
`-ffunction-sections` / `--gc-sections`.

## Specifications

`docs/spec/` is gitignored — drop spec documents there locally. The
implementation follows the PSIA **PKOC NFC Card Specification v1.1**
(Rev0, 12/1/2023).

## License

Two components, two licenses — by design:

| Path | Runs on | License |
| ---- | ------- | ------- |
| `card/` | the card | Apache-2.0 |
| `core/`, `pkoc/`, `tests/` | the reader | GPL-3.0-or-later **or** commercial |

The applet is permissive so anyone can adopt it — PKOC is an open
standard, and the card side should not need a licensing conversation. The
reader library is where the commercial option applies.

The two never link: different devices, no shared binary, communicating
only over the APDU wire protocol. See [LICENSE.md](LICENSE.md) for the
full reasoning and [LICENSING](LICENSING) for commercial inquiries.
