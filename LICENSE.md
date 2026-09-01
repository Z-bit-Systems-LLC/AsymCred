# AsymCred — Licensing

Copyright (C) 2026 Z-bit Systems, LLC. All rights reserved.

This repository contains **two components under two different licenses**.
Which one applies depends only on which directory a file is in, and every
source file states its own license in an SPDX header.

| Path | Component | License |
| ---- | --------- | ------- |
| `card/` | PKOC JavaCard applet — the code that runs **on the card** | Apache-2.0 |
| everything else (`core/`, `pkoc/`, `tests/`) | The C11 reader library — the code that runs **on the reader** | GPL-3.0-or-later **or** commercial |

The split is deliberate, not an accident of history. The rationale is in
[Why the split works](#why-the-split-works) below.

---

## The reader library — GPL-3.0-or-later or commercial

`core/`, `pkoc/` and `tests/` are offered under a **dual-license** model.
You may use them under either, at your choice:

### Option 1 — GNU General Public License v3.0 or later

Free for any use that is itself distributed under a GPL-compatible
license. The full GPL text is in
[LICENSE-GPL-3.0.txt](LICENSE-GPL-3.0.txt). These files carry the SPDX
identifier `GPL-3.0-or-later`.

In broad terms, the GPL requires that if you distribute software
(including firmware) that incorporates the reader library, you must also
distribute the complete corresponding source code of that combined work
under the GPL, including any modifications you have made. **This is not
legal advice; if you are unsure whether your distribution model is
GPL-compatible, consult a qualified attorney or contact us about a
commercial license.**

### Option 2 — Commercial License

If you cannot or do not wish to comply with the GPL — typical reasons
include shipping closed-source embedded firmware, integrating into a
proprietary product, or wanting indemnification — Z-bit Systems offers a
paid commercial license that grants the same code under terms compatible
with proprietary distribution.

Inquiries: see [LICENSING](LICENSING).

A signed commercial license supersedes the GPL terms **for the licensee
only**, for the use cases covered by their agreement. The public source
tree remains available under the GPL.

## The card applet — Apache-2.0

`card/` is licensed under the Apache License 2.0. The full text is in
[card/LICENSE-APACHE-2.0.txt](card/LICENSE-APACHE-2.0.txt); those files
carry the SPDX identifier `Apache-2.0`.

Apache-2.0 is permissive: you may load this applet onto cards, modify it,
and ship it in a proprietary product without releasing your source and
**without needing a commercial license from us**. That is intentional.
PKOC is an open credential standard, and a card applet that anyone can
adopt without a licensing conversation is the point.

Note that Apache-2.0 includes an express patent grant and a
patent-retaliation clause, which the GPL-3.0 side expresses differently.
If that distinction matters to your deployment, read both texts rather
than assuming they are interchangeable.

---

## Why the split works

Mixed licensing inside one repository invites the question "do these
conflict?" Here they cannot, because **the two components never combine
into one work**:

- They run on **different physical devices**. The applet executes inside
  the card's secure element; the C library executes on the reader's MCU.
- They are **never linked**. There is no build in which one becomes part
  of the other — no shared binary, no shared address space, no shared
  process. `card/` is deliberately outside the CMake build.
- They communicate **at arm's length over a documented wire protocol** —
  ISO 7816-4 APDUs over NFC, defined by the PSIA PKOC specification, not
  by either implementation.

That is the textbook case of two separate programs, not one derivative
work. The GPL's reciprocal obligations attach to a combined work; no
combined work is created here. This is not the debatable territory of
dynamic linking or plugins — it is two independent executables on two
separate pieces of hardware exchanging bytes.

One direction is worth noting anyway, in case the components are ever
brought closer together: **Apache-2.0 is one-way compatible with
GPL-3.0**. Apache-2.0 code may be incorporated into a GPL-3.0 work (the
result is GPL-3.0); GPL-3.0 code may *not* be incorporated into an
Apache-2.0 work. So if some future shared code moves from `card/` into
the reader library, that direction is fine. The reverse is not.

(Apache-2.0 is *not* compatible with GPL **v2** — its patent and
indemnification terms are considered additional restrictions. This
repository is GPL-3.0-**or-later**, so that incompatibility does not
apply here. It would matter if you tried to combine the reader library
with a GPLv2-only project.)

## Contributions

Contributions are accepted under the license of the directory they touch:

- Contributions to `card/` are licensed under **Apache-2.0**.
- Contributions to everything else are licensed under
  **GPL-3.0-or-later**, and you agree that Z-bit Systems may re-license
  them under the commercial license.

A formal Contributor License Agreement (CLA) will be put in place before
accepting external contributions; until then, only contributions from
Z-bit employees and contractors under work-for-hire are accepted.

Do not move code between `card/` and the rest of the tree without
considering the licensing consequence — the direction matters (see
above), and the SPDX header must be updated to match its new home.
