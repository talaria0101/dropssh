# Open bugs and requested features

Everything still outstanding, as of 2026-09-27. Ordered by what blocks what.
Each bug says what it looks like, because a defect that presents as
something else is the expensive kind.

**This list is split.** Everything concerning the relay, its wire protocol, and
the verbs that speak to it is in [`relay-issues.md`](relay-issues.md), which is
where that work should be picked up from. What remains here is the two items
that are about the ssh server instead.

Status: nothing is fixed. The tree is at one commit with CI green on 11 jobs
and `tests/e2e.sh` 9/9.

Every claim was checked against the source before it was written down, and one
was wrong and is corrected in place: **B8** in the relay list originally said
`dropssh relay --status` prints a hardcoded count. It does not exist at all. The
original text is kept there so the correction is visible, because a bug list
with an unverified bug in it is worth less than a shorter one.

Where a bug names a file and a line, that is the line it was verified against,
not an approximate location.

---

## The relay work, in one place

| | |
| --- | --- |
| **B1**-**B5** | the multiplexed reverse path. **B4** is the root cause: `ws_read` is a byte stream, not a frame reader. |
| **B6**-**B10** | the fork that copies a TLS context, absent backpressure, no relay status, no relay limits, and an e2e that never reaches a real relay. |
| **B11**-**B12** | in the relay, not here: a bare node frame is dropped in silence, and a bogus operator id is rewritten rather than rejected. |
| **B13**-**B14** | in the relay author's own reference operator, and both stop it running. |
| **R1**-**R6**, **R8**, **R10**-**R11** | a framing probe as a script, a real-relay CI job, `doctor`, `--json` as a dead flag, a `pair` verb, a `config` verb, fetching the protocol reference, two **concurrent** sessions, and a negative test for the id rule. |

Full text, with what each looks like:
[`relay-issues.md`](relay-issues.md).

---

# What is left here

Both are server-side. Neither is a transport problem.

## R7. Ship the CA bundle in the release

It is fetched at build time for mbedTLS's benefit and then discarded, so a
clean machine has none and the first connection cannot verify anything. One
file in the tarball fixes it.

## R9. A `--passwd-file` option patched into dropbear

The best remaining change to the product, and it removes the `LD_PRELOAD`
dependency and the glibc/musl split with it. `dropbear` would read its passwd
database from a file, `serve` would not need a shim, and a static server would
become usable. The e2e case: a server with **no** `LD_PRELOAD` in its
environment still authenticates.

