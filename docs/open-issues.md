# Open bugs and requested features

Everything still outstanding. Ordered by what blocks what. Each bug says what
it looks like, because a defect that presents as something else is the
expensive kind.

**Read the status line before the list:** the relay half of this work is done,
and one entry in it turned out to describe the relay incorrectly.

**This list is split.** Everything concerning the relay, its wire protocol, and
the verbs that speak to it is in [`relay-issues.md`](relay-issues.md), which is
where that work should be picked up from. What remains here is the two items
that are about the ssh server instead.

## Status, 2026-09-28

**The relay work is done.** B1-B10, R1, R3, R4, R5, R6, R10 and R11 were fixed
in commit `67308d8`; the multiplexed reverse path is implemented and was
measured live against `tcp.ssh.relay.ajam.dev` (two concurrent sessions on one
node socket, a 270177-byte transfer byte for byte). `tests/e2e.sh` is 19/19 and
`tests/mux-probe.py` pins the relay's framing rules.

What remains is **R2** (a scheduled real-relay CI job, which needs a network and
a credential) and the two server-side items below.

Every claim was checked against the source before it was written down, and one
was wrong and is corrected in place: **B8** in the relay list originally said
`dropssh relay --status` prints a hardcoded count. It does not exist at all. The
original text is kept there so the correction is visible, because a bug list
with an unverified bug in it is worth less than a shorter one.

⛔ **AND ONE MORE WAS WRONG, AND IT MATTERED MORE.** **B11** claimed the relay
"silently drops" a bare node frame. Re-measured live on 2026-09-28, 3/3: the
node socket is closed with **1009 `bad multiplex frame`** and the operator with
**1011**. Five places in this tree repeated the claim; all five are corrected,
and `tests/mux-probe.py` asserts the 1009 close so the claim is in a test and
not in prose. A bug list with a bug *in the thing it describes* sends an
implementer looking for silence they will never see.

Where a bug names a file and a line, that is the line it was verified against,
not an approximate location.

---

## The relay work, in one place

| | |
| --- | --- |
| | |
| --- | --- |
| **B1**-**B10** | **fixed in `67308d8`.** The multiplexed reverse path, one decoder in `ws.c`, one reader and one writer per socket, no fork, the relay's advertised limits honoured, `relay --status`, and two concurrent sessions in the gate. |
| **B11** | **the claim was wrong.** A bare node frame is closed 1009 `bad multiplex frame`, not dropped in silence. Measured 2026-09-28, 3/3, and asserted by `tests/mux-probe.py`. |
| **B12** | open, in the relay. Not exploitable; the consequence for a client is that the id in an operator frame must not be treated as addressing. |
| **B13**-**B14** | open, in the relay author's own reference operator. Both stop it running; both are documented. |
| **R1**, **R3**-**R6**, **R10**, **R11** | **fixed in `67308d8`**: `tests/mux-probe.py`, `doctor`, `--json`, `pair`, `config`, two concurrent sessions, and a negative test for the id rule. |
| **R2**, **R8** | open. A real-relay CI job, and fetching the relay's reference operator pinned. |

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

