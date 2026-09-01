# PKOC JavaCard Applet

The **card half** of PKOC. JavaCard applet implementing the PSIA PKOC NFC
Card 1.1 specification: it generates a P-256 key pair on-card at install
(the private key never leaves the card) and answers the SELECT /
AUTHENTICATE flow.

The reader half lives in [`../pkoc/`](../pkoc/) — same repository, same
specification, opposite ends of the exchange. Between them they close the
loop: `card/` signs a transaction identifier, `pkoc/` verifies that
signature and derives the credential.

```
../pkoc/  (reader, C11)  ──── SELECT ──────────▶  card/  (JavaCard)
                         ◀─── 5C version ──────
                         ──── AUTHENTICATE ────▶
                         ◀─── 5A key, 9E sig ──
```

## Features

- **SELECT** (AID `A000000898000001`): returns a protocol version TLV.
- **AUTHENTICATE** (CLA=80, INS=80): signs the 16-byte transaction ID with
  ECDSA-SHA256, returns the 65-byte uncompressed public key plus the
  64-byte raw R‖S signature.
- On-card P-256 key generation at install time.
- Forward-compatible TLV parsing — unknown tags silently ignored, as the
  spec requires.

### Protocol version: this applet reports 1.1

The applet answers SELECT with `5C 02 01 01` (v1.1), while the PKOC 1.1
specification's own Variables table and worked example both use `01 00`
(v1.0). Both are handled — the reader library negotiates against whatever
list the card advertises and echoes the agreed value back, and never
hardcodes either — but the divergence is deliberate to record rather than
quietly "fix". See the same note in [`../CLAUDE.md`](../CLAUDE.md).

## Prerequisites

| Tool | Version | Location |
|---|---|---|
| JDK 8 | Temurin 8.0.482+ | `C:\Program Files\Eclipse Adoptium\jdk-8.0.482.8-hotspot` |
| Apache Ant | 1.10.15 | `C:\tools\apache-ant-1.10.15` |
| JavaCard SDK | 3.0.4 | `card/sdks/jc304_kit` (git-ignored) |
| ant-javacard | v26.02.22 | `card/lib/ant-javacard.jar` (git-ignored) |
| jCardSim | 3.0.5-SNAPSHOT | `card/lib/jcardsim-3.0.5-SNAPSHOT.jar` (git-ignored) |

JDK 8 is not optional — the JavaCard SDK requires it.

### First-time setup

`sdks/` and `lib/*.jar` are git-ignored (the SDK clone alone is ~100 MB),
so a fresh checkout needs them fetched. From `card/`:

```bash
# JavaCard SDKs
git clone --depth 1 https://github.com/martinpaljak/oracle_javacard_sdks.git sdks

# ant-javacard
mkdir -p lib
curl -sL -o lib/ant-javacard.jar \
  "https://github.com/martinpaljak/ant-javacard/releases/download/v26.02.22/ant-javacard.jar"

# JUnit 4.13.2 + hamcrest-core 1.3 into lib/ as well
```

jCardSim 3.0.5 must be built from [source](https://github.com/licel/jcardsim)
— the 2.2.2 build on Maven Central lacks ECDSA-SHA256, which is exactly
what this applet needs. Building it requires Maven and `JC_CLASSIC_HOME`
pointed at `sdks/jc305u3_kit`.

## Build

```bash
# Per shell session; does not modify system JAVA_HOME
export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-8.0.482.8-hotspot"
export PATH="/c/tools/apache-ant-1.10.15/bin:$JAVA_HOME/bin:$PATH"

ant build     # -> build/pkoc.cap
ant test      # jCardSim, no physical card needed
ant clean
```

If the SDK and jars live elsewhere, override the paths rather than copying
them in:

```bash
ant -Djckit.dir=/path/to/jc304_kit -Dlib.dir=/path/to/lib test
```

## Layout

```
card/
├── build.xml                                # Ant build (build + test targets)
├── src/com/zbitsystems/pkoc/PkocApplet.java
├── test/com/zbitsystems/pkoc/PkocAppletTest.java
├── lib/                                     # jars (git-ignored)
├── sdks/                                    # JavaCard SDKs (git-ignored)
└── build/
    └── pkoc.cap                             # committed on purpose - see below
```

### Why `build/pkoc.cap` is committed

`build/` is ignored except for `pkoc.cap`, which is tracked deliberately:
Cred-Bench embeds that exact artifact as a resource
(`src/Core/Core.csproj` → `EmbeddedResource ... pkoc.cap`) to program
blank cards at runtime. CAP files embed build metadata, so a rebuild is
not byte-identical to the committed copy — replace it only intentionally,
not as a side effect of running `ant build`.

## Test coverage

8 tests, all passing on jCardSim:

| Test | Validates |
|---|---|
| testSelectReturnsProtocolVersion | SELECT response `5C 02 01 01` |
| testAuthenticateReturnsPublicKeyAndSignature | Response shape `5A 41 [65] 9E 40 [64]` |
| testSignatureIsVerifiable | Signature verifies against the transaction ID |
| testConsistentPublicKeyAcrossAuthentications | Same key every time |
| testDifferentSignaturesForDifferentTransactions | Unique signature per transaction |
| testUnsupportedInstructionReturnsError | SW `6D00` for unknown INS |
| testAuthenticateWithTruncatedDataReturnsError | Rejects short command data |
| testAuthenticateMissingTransactionIdReturnsError | Rejects a missing `0x4C` TLV |

## Loading onto a physical card

Use [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro):

```bash
gp --install build/pkoc.cap   # default GP keys (404142...)
gp --list                     # verify
```

Target hardware needs JavaCard 3.0.4+, ECC P-256, and NFC (ISO 14443-A).
NXP JCOP4 or Infineon SLE97 series work.

## License — unresolved

The two files here carry `SPDX-License-Identifier: Apache-2.0` from their
previous home in Cred-Bench. The rest of this repository is
GPL-3.0-or-later or commercial (see [`../LICENSE.md`](../LICENSE.md)).

The headers were left exactly as they were rather than relicensed as part
of a file move. Which license this applet should carry here is a decision
for the copyright holder, not a mechanical consequence of moving
directories.
