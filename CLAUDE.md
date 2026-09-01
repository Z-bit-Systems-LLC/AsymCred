# CLAUDE.md — guidance for working on AsymCred

This file captures the locked architectural decisions and coding rules for
this project so future Claude sessions can pick up cold without re-deriving
them. Read it before making suggestions or writing code.

## What this project is

An embedded-friendly implementation of **asymmetric credential standards**
for access control readers, designed to sit alongside
[OSDP-Embedded](../OSDP-Embedded) rather than inside it. OSDP-Embedded
carries the credential over the wire; AsymCred is what produces the
credential in the first place.

Owned by Z-bit Systems. Same author, same conventions, same dual license.

The first (and currently only) standard implemented is **PKOC** — Public
Key Open Credential, PSIA, ECC P-256, the card's public key *is* the
credential.

## Locked architectural decisions

Agreed with the user on 2026-09-01. Do not silently revise them; if a task
seems to need a change, raise it explicitly with the user first.

1. **Scope is PKOC 1.1 only.** Aliro, PIV/CAK, and the OSDP crypto-auth
   message family (`osdp_GENAUTH` / `osdp_CRAUTH` / transparent-mode
   `osdp_XWR` / `osdp_XRD`) were considered and deliberately deferred.
   Adding one is a scope decision for the user, not a refactor.
2. **Reader-side (PD) topology.** The library runs on the reader: it
   drives the card over ISO-DEP/APDU, verifies the signature locally, and
   hands the application a finished credential to report over OSDP
   (`osdp_RAW`). It is *not* a host-side/tunnelled design — nothing here
   tunnels APDUs to an ACU.
3. **Crypto is HAL-only.** The consumer supplies SHA-256, ECDSA P-256
   verify, and a CSPRNG through `asymcred_crypto_t`. The library vendors
   no crypto, mirroring OSDP-Embedded's `osdp_sc_crypto_t` rule.
4. **Language: C11**, freestanding-friendly. No malloc, no globals, no
   OS calls, no I/O. All buffers caller-owned. All functions reentrant.
5. **No I/O in the library.** The PKOC transaction is a step machine
   (`next_apdu` / `feed`), so it works from an interrupt-driven NFC stack
   as readily as a blocking PC/SC one. `asymcred_pkoc_run()` is a thin
   convenience wrapper over that, not a second implementation.
6. **Build system: CMake.** Test framework: **Unity** (vendored).
7. **Modularity by concern.** `core` holds what every credential standard
   needs (TLV, APDU); each standard gets its own target. A reader that
   only derives a credential from an already-read key must not link the
   state machine.

## Module layout

```
core/include/asymcred/
  asymcred_types.h     # status codes shared by everything
  asymcred_tlv.h       # PKOC-dialect TLV (1-byte tag, 1-byte length)
  asymcred_apdu.h      # ISO 7816-4 case-4 short APDU build/split
  asymcred_crypto.h    # crypto HAL (consumer-supplied)

core/src/shared/
  tlv.c
  apdu.c

pkoc/include/asymcred/
  asymcred_pkoc.h      # transaction state machine + credential derivation

pkoc/src/
  pkoc.c               # SELECT -> AUTHENTICATE -> verify state machine
  pkoc_credential.c    # 256 / 75 / 64-bit derivation from the X component

tests/
  support/test_crypto.{c,h}  # real SHA-256 + scriptable ECDSA stub
  vendor/unity/              # vendored Unity (MIT)
  test_tlv.c  test_apdu.c  test_pkoc.c  test_pkoc_credential.c

docs/spec/               # gitignored; drop spec PDFs/text here
```

### CMake targets

| Target            | Contents                                | Linked by         |
| ----------------- | --------------------------------------- | ----------------- |
| `asymcred::core`  | TLV codec, APDU helpers                 | everything        |
| `asymcred::pkoc`  | PKOC state machine + credential derive  | PKOC readers      |

## Reserved for phase 2 — the card side

The user has an existing **PKOC JavaCard applet** (currently at
`../Cred-Bench/src/Applet/`, `com.zbitsystems.pkoc.PkocApplet`) that is
moving into this repository. It is already written and working; phase 2 is
a relocation, not new development.

Reserve `card/` for it. Do not start writing a card-side applet — ask the
user for the move rather than reimplementing what exists.

Note the applet is Apache-2.0 in its current home, while this repo is
GPL-3.0-or-later / commercial dual. Raise the license question with the
user at move time rather than silently relicensing.

## Reference material

- **Spec**: `docs/spec/PSIA-PKOC-NFC-Card-1.1.txt`, converted with
  `pdftotext -layout` from
  `H:\Drive\Z-bit\Documents\Access Control\PKOC\PSIA-NFC-Card_1.1-Approved.pdf`.
  Gitignored (see `docs/spec/.gitignore`), ~298 lines. Grep it rather than
  guessing at any tag, length, APDU field, or flow step.
- **More PKOC documents** in the same folder, not yet converted and not
  yet in scope: `PKOC Credential Spec v 1.03.pdf`, `pkoc-osdp-acu*.pdf`
  (the OSDP-transport binding), `PSIA_PKOC-ECDHE-v2*` (the v2/ECDHE
  direction), `PSIA_PKOC-OBF*`. Convert into `docs/spec/` when a task
  reaches them.
- **Cred-Bench** (`../Cred-Bench`) — behavioral oracle. `PKOCDetector.cs`
  does the reader half in C#; `PkocApplet.java` is the card half;
  `docs/PKOC.md` documents both. Useful for cross-checking. Note it
  implements identification-only mode (zeroed reader identifier, no
  signature requirement), so it is not a model for an access decision.
- **OSDP-Embedded** (`../OSDP-Embedded`) — the conventions this repo
  copies, and the consumer of the credentials this library produces.

## Facts pinned down from the spec

Things that were ambiguous until checked, recorded so nobody re-derives
them:

- **The card signs the transaction identifier and nothing else.** Not
  `txid || reader_id`, not the AUTHENTICATE command data. Spec flow step
  6 says so in prose, and the spec's own worked example was verified
  independently with openssl: the example signature is a valid
  ECDSA-P256-SHA256 over the raw 16 transaction-ID bytes. That vector is
  in `tests/test_pkoc.c`, along with the openssl-computed digest.
- **The SELECT response carries a *list* of versions**, "sorted by
  largest (most recent) first", not a single one. The reader picks. The
  library negotiates: caller preference order first, else the card's
  first entry.
- **The spec's protocol version is `0x0100`** (its "Variables" table and
  its example). The Cred-Bench applet reports `0x0101`. Both are handled
  — the library echoes whatever was negotiated and never hardcodes one —
  but do not "fix" one to match the other without asking.
- **Transaction identifier is 16 bytes** in the AUTHENTICATE command
  (hence the spec's fixed `Lc = 0x38`), even though the TLV table
  separately allows 16..65. We send 16.
- **Signature is raw R||S, 64 bytes**, explicitly "not the ASN.1
  encoding" (flow step 6).

## Coding rules

- C11. Freestanding-only headers (`<stdint.h>`, `<stddef.h>`,
  `<string.h>`, `<stdbool.h>`). No `<stdio.h>`, `<stdlib.h>`, no malloc,
  no globals, no thread-local storage.
- All public symbols prefixed `asymcred_`. Internal helpers `static`.
- Return `asymcred_status_t` from anything that can fail; never
  errno-style global state.
- No undefined behavior on invalid input. Decoders defend against
  truncated, oversized, and malformed data; they report errors, they do
  not crash.
- **Every source file (`.c`, `.h`, `CMakeLists.txt`) starts with an SPDX
  header**:

  ```
  // SPDX-License-Identifier: GPL-3.0-or-later
  // Copyright (C) 2026 Z-bit Systems, LLC
  ```

  `#` comments for CMake, `//` for C. `LICENSE.md` is canonical; do not
  write alternative license text into source files.

## Security rules specific to this library

These are not style preferences — getting them wrong produces a reader
that opens doors it should not.

- **A public key is only a credential once its signature has verified.**
  `asymcred_pkoc_result()` returns `ASYMCRED_ERR_INVALID_STATE` unless
  the transaction reached `_COMPLETE`, and a verification failure moves
  it to `_FAILED` instead. Do not add a path that hands out
  `pkoc->public_key` around that gate.
- **`require_signature = false` is enrolment/diagnostics only.** It
  exists because reading a key off a card is a real workflow. It must
  never become the default, and the result it produces
  (`signature_verified == false`) must never gate access.
- **The transaction identifier must come from a CSPRNG.** It is the only
  thing that makes the card's signature fresh; a counter or timestamp
  makes a captured response replayable.
- **Verification failure is not a soft error.** Do not degrade it to a
  warning, a retry, or a "signature unavailable" result.

## Testing

- Unity is vendored under `tests/vendor/unity/`.
- The crypto HAL is bound in `tests/support/test_crypto.c`: SHA-256 is a
  real implementation (with known-answer tests, including the 56-byte
  padding boundary), ECDSA verify is a scriptable stub that records its
  arguments. That proves the state machine's contract — including the
  exact digest handed to verification — but proves no verification maths,
  because the library contains none.
- 45 tests across 4 suites. The spec's worked example is reproduced byte
  for byte: both C-APDUs, both R-APDUs, the derived credentials.
- When adding a codec or message, add a round-trip test and at least one
  negative test (truncated, wrong length, malformed).

## Out of scope (do not introduce without explicit user approval)

- Dynamic memory allocation, OS/RTOS calls, or I/O anywhere in `core/`
  or `pkoc/`.
- A vendored crypto library. The consumer supplies the primitives.
  (Binding micro-ecc *for tests only*, gated like OSDP-Embedded's
  `vendor/tiny-aes/`, would be a reasonable proposal — it would let the
  suite verify the spec's signature end to end instead of stubbing. Ask
  first.)
- Any credential standard other than PKOC (see decision 1).
- Host-side / OSDP-tunnelled operation (see decision 2).
- Extended-length APDUs, command chaining, `GET RESPONSE` (`61xx`/`6Cxx`).
  ISO-DEP reassembly belongs in the consumer's PCD driver; this library
  is handed complete APDUs.
- BLE or UWB transports. PKOC 1.1 as implemented here is the NFC card
  specification.

## Building

No CMake or compiler on `PATH` in this environment. Visual Studio 2022
Professional ships both:

```powershell
$cmake = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
& $cmake -S . -B build-main -G "Visual Studio 17 2022" -A x64
& $cmake --build build-main --config Debug
& "$(Split-Path $cmake)\ctest.exe" --test-dir build-main -C Debug --output-on-failure
```

MSBuild skips a rebuild when a restored file keeps an old timestamp —
touch it (`(Get-Item path).LastWriteTime = Get-Date`) if a change seems
not to take.

## When in doubt

Ask the user. The user prefers iterative agreement on architecture over
silently broadening scope.
