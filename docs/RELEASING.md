# Releasing AsymCred

How a Z-bit Systems maintainer ships a new version of AsymCred, and what
CI does along the way. The equivalent document in OSDP-Embedded is
`docs/PUBLISHING.md`; this repo's process is deliberately shorter,
because **AsymCred publishes nothing to any package registry.**

There is no crate, no npm package, no binary distribution. AsymCred is a
source library that consumers vendor or pull in with CMake
`FetchContent`. A release is therefore two things: an annotated `v*` tag
that built green, and a GitHub Release whose notes say what changed.
GitHub generates the source archives from the tag itself. Nothing in the
process is irreversible, and nothing needs an approval gate.

## Continuous integration

`ci/azure-pipelines.yml` runs on every push to `main`, every PR, and
every `v*` tag. All jobs run on the self-hosted **Default** pool's Linux
agents — the same Proxmox LXC agents OSDP-Embedded uses, provisioned by
that repo's `scripts/provision-linux-agent.sh`.

| Job           | Template            | What it proves |
| ------------- | ------------------- | -------------- |
| `build_c`     | `ci/build-c.yml`    | Compiles clean under GCC with the strict warning set as errors, and all tests pass (x86_64 Release). |
| `sanitize`    | `ci/sanitize.yml`   | The same suite passes under AddressSanitizer + UndefinedBehaviorSanitizer. |
| `cross_arm64` | `ci/cross-arm64.yml`| The library and tests compile and link for `aarch64-linux-gnu`. Build-only — an x64 agent cannot run ARM binaries. |

Three things worth knowing about that table:

- **The sanitizer job is not redundant.** AsymCred's TLV and APDU
  decoders are required to report errors rather than crash on truncated,
  oversized, and malformed input. The negative tests feed them exactly
  that, but a one-past-the-end read of a caller-owned buffer usually
  *passes silently* without a sanitizer, and no warning flag can see it.
  This job is what turns those tests into evidence.
- **A sanitizer *crash* is not a sanitizer *finding*.** A genuine
  detection always prints an `ERROR: AddressSanitizer: <kind>` line with
  a stack. A burst of bare `AddressSanitizer: DEADLYSIGNAL` lines ending
  in a SIGSEGV with no report is the runtime failing to run at all —
  read the "Sanitizer environment" step, not the C code. The two causes
  seen on these agents are LeakSanitizer being denied `ptrace` under
  unprivileged LXC (hence `detect_leaks=0`) and an ASLR entropy
  (`vm.mmap_rnd_bits`) too high for the GCC 12 ASan runtime, which is
  fixed on the agent with `sysctl -w vm.mmap_rnd_bits=28`.
- **The cross job is the portability claim.** The README calls the
  library embedded-friendly; `cross_arm64` is the standing evidence.
  Different alignment rules (`-Wcast-align` is far noisier on ARM) and a
  different plain-`char` signedness are exactly the hazards a
  byte-oriented TLV/APDU codec runs into. It asserts the output is a
  genuine aarch64 ELF, so a toolchain file that silently failed to take
  effect can't produce a green-but-worthless x86 build.
- **Windows/MSVC is not in CI.** It is covered by running
  `scripts/Check-Code.ps1` on a developer workstation, which is where
  this library is actually authored. If MSVC coverage ever needs to be
  enforced rather than trusted, that is a Windows agent, not a change to
  these templates.

`ASYMCRED_WERROR=ON` is set by the CI jobs only. The strict warning set
in `CMakeLists.txt` is always on, but warnings become *errors* solely in
CI — so a new warning can never land here, while a consumer building
AsymCred inside their own tree with a compiler version we have never
seen is never broken by a diagnostic.

There is deliberately **no `package` job**: with no artifact to build,
one would only produce an empty bundle. If AsymCred ever grows a
packaged artifact, add a tag-gated `package` job rather than widening one
of the build jobs.

### Pre-push checks

`scripts/Check-Code.ps1` runs the same gates locally:

```pwsh
./scripts/Check-Code.ps1              # every applicable gate
./scripts/Check-Code.ps1 -SkipCross   # skip the aarch64 gate
./scripts/Check-Code.ps1 -Asan        # attempt the sanitizer gate on Windows too
```

It is not wired to a git hook — run it by hand before pushing.
`New-Release.ps1` also runs it once before tagging.

A green run **on Windows is a weaker signal than a green pipeline**. The
sanitizer gate is skipped there by default (MSVC has no UBSan, and its
ASan needs the clang_rt runtime resolvable at test time) and the
cross-compile gate is skipped unless `aarch64-linux-gnu-gcc` is on PATH.
Those show as `SKIP` in the summary rather than quietly passing, and the
exit code still reports how many were skipped.

## The release process

Three steps. Step 2 happens in Azure DevOps; the rest are local commands.

### 1. Cut the release locally

```pwsh
./scripts/New-Release.ps1                        # patch bump (0.1.0 -> 0.1.1)
./scripts/New-Release.ps1 -IncrementType Minor   # 0.1.0 -> 0.2.0
./scripts/New-Release.ps1 -IncrementType Major   # 0.1.0 -> 1.0.0
./scripts/New-Release.ps1 -Version 1.0.0         # explicit
./scripts/New-Release.ps1 -DryRun                # preview, no writes
```

`New-Release.ps1` validates the repo (on `main`, clean tree, synced with
origin), resolves the new version, bumps it via `Set-Version.ps1`, runs
the `Check-Code.ps1` gates so the tagged commit is known-green, then
commits, tags `v<version>`, and pushes `main` + the tag.

### 2. Let the pipeline verify the tag

Pushing the tag triggers `ci/azure-pipelines.yml`. Wait for it to go
green. **If it fails, fix forward and cut a new patch version — do not
move the tag.** A moved tag invalidates every archive URL and every
checkout anyone already made from it.

Pushing `main` and then the tag queues two builds of an identical tree.
The templates detect this: on the `refs/heads/main` run of a commit whose
subject starts with `Bump version to`, the heavy steps short-circuit. The
tag run — the one that gates the release — always runs in full.

### 3. Publish the GitHub Release

```pwsh
./scripts/Publish-GitHubRelease.ps1 -Tag v1.2.3 -DryRun   # preview notes
./scripts/Publish-GitHubRelease.ps1 -Tag v1.2.3 -Draft    # stage to edit
./scripts/Publish-GitHubRelease.ps1 -Tag v1.2.3           # publish
```

This is what makes the release visible to anyone watching the repo. The
script refuses to run if the tag isn't on origin or a release already
exists for it, and it never creates or moves a tag.

**Notes are generated from the commits since the previous tag**, grouped
by Conventional Commit type — the same approach OSDP-Embedded and
OSDP.Net use. This is the default and the norm: there is no
`CHANGELOG.md` to maintain and nothing needs writing between releases. It
does mean commit subjects *are* the release notes, so write them
accordingly. AsymCred's history so far uses plain imperative subjects
rather than Conventional Commit prefixes, so expect most bullets under
the "Other" heading until that changes.

`-NotesFile <path>` replaces the generated notes with written prose. This
is the exception, reserved for a release whose significance a commit list
would misrepresent — a 1.0.0, or a release that changes the trust model.
Keep such files in `docs/release-notes/`. Do not reach for it routinely.

**This step is manual and easy to forget.** `New-Release.ps1` prints the
command at the end of step 1 as a backstop; until it runs, the release is
invisible to anyone watching the repo.

## Versioning

The canonical version is the `project(asymcred VERSION x.y.z ...)` line
in the top-level `CMakeLists.txt`. That is the *only* place in the repo
that carries the library version — there is no package manifest to keep
in sync.

`card/build.xml`'s `version="1.1"` is **not** the library version. It is
the CAP package version of the PKOC applet, a property of the standard
the applet implements. `Set-Version.ps1` never touches it, and neither
should you when bumping a release.

`Get-Version.ps1` reads the version; `Set-Version.ps1` writes it. Both
enforce numeric `MAJOR.MINOR.PATCH`.

**No pre-release suffixes.** CMake's `project()` VERSION rejects
`0.2.0-rc.1`, and AsymCred has no second manifest (OSDP-Embedded keeps
the full SemVer in `rust/Cargo.toml`) to hold the suffix. Rather than
record a version that disagrees with its tag, or park the real string in
a variable nothing reads, pre-releases are simply not used here. If they
ever become necessary, add the canonical string somewhere the build
actually consumes it and teach `Get-Version.ps1` to prefer it.

## The card applet is released separately

`card/` is a different toolchain (Java, Ant, JDK 8, a ~100 MB gitignored
JavaCard SDK) and is deliberately not in CI or in the CMake build. Its 8
jCardSim tests are a manual gate:

```sh
cd card && ant test
```

`card/build/pkoc.cap` is a committed artifact and is **not** rebuilt as
part of cutting a release — Cred-Bench embeds that exact file, and CAP
files carry build metadata, so a rebuild is not byte-identical. See
`CLAUDE.md` and `card/README.md` before touching it.

## One-time setup

The pipeline has to be created in Azure DevOps once:

1. In the **Z-bitSystems** organisation, create a new pipeline pointing
   at this repository, existing YAML file, path `ci/azure-pipelines.yml`.
2. Confirm the **Default** pool's Linux agents advertise the
   `aarch64Toolchain` user capability — `cross_arm64` demands it, and an
   agent without it leaves the job visibly queued rather than failing
   mid-build. OSDP-Embedded's `scripts/provision-linux-agent.sh` sets it.
3. Add the build-status badge to `README.md` once the pipeline has a
   definition ID:

   ```markdown
   [![Build Status](https://dev.azure.com/Z-bitSystems/AsymCred/_apis/build/status%2FAsymCred-CI?branchName=main)](https://dev.azure.com/Z-bitSystems/AsymCred/_build/latest?definitionId=<ID>&branchName=main)
   ```

   The badge is left out of the README until then rather than committed
   broken.

Publishing releases additionally needs the GitHub CLI (`gh`), installed
and authenticated with `gh auth login`.
