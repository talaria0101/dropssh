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
node socket, a 270177-byte transfer byte for byte).

**Updated 2026-09-28.** `tests/e2e.sh` is **34/34** and `tests/mux-probe.py`
carries **thirteen** cases, up from the nine it started this session with. Five
of the new ones are for the three known-unguarded items, and **U1, U2 and U3
are all closed**; see the three full entries at the end of
[`relay-issues.md`](relay-issues.md), and read U3's for a claim in this tree
that measurement falsified.

Four defects were found by writing the cases rather than by reading the code,
and three of them were **silent data loss or a wrong refusal**:

| found by | what it was |
| --- | --- |
| the 300 KB case (#10) | `relay.c` clamped an operator's frame to the node's `maxFrameBytes`, so **300000 bytes arrived as 65536** and 234464 were lost with no close and no log |
| U2's ownership case | `ws_close` NULLed `ws->t` without setting `ws->closed`, so a write on a closed or moved-from session **dereferenced NULL** |
| U2/U3's concurrency read | `NameSlot.node` was a bare pointer **into** a heap `NodeCtx` the node's own thread freed, so a writer used freed memory |
| rebuilding the release | `scripts/build-dropbear.sh`'s idempotency marker was a string in **neither** the patch nor the patched source, so the **second `build.sh --full` in a clean checkout always failed** |

What remains is **R9** (a `--passwd-file` patched into dropbear) and, from the
relay list, **R2** and **R8** — both of which are now BUILT and both of which
need something this repository does not have; see their entries.

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
| **R2** | **BUILT, cannot run here.** `tests/relay-session.sh` and a scheduled job that carries a real session, a 270 KB transfer by sha256, and two concurrent sessions on one node socket. It needs a pair from the relay's `POST /v1/pair`, which is per-pair AND per-role and cannot be obtained from the outside. The job reports three outcomes and never reports a missing credential as a pass. |
| **R8** | **DONE.** There is no repository to pin: the relay publishes a Worker and what it SERVES is the thing a client talks to. `scripts/fetch-relay-spec.sh` fetches the served document, records the version from `/health`, and re-checks the five facts this tree measured. At `2026-09-28-r12`, 5/5 hold. It was `r11` when our measurements were taken, the same day. |

Full text, with what each looks like:
[`relay-issues.md`](relay-issues.md).

---

# What is left here

Both are server-side. Neither is a transport problem.

## R7. Ship the CA bundle in the release -- DONE 2026-09-28

It was fetched at build time for mbedTLS's benefit and then discarded, so a
clean machine had none and the first connection could not verify anything.

The release now ships one, and the binary looks for it **beside itself**
resolved from `/proc/self/exe` rather than `argv[0]` — a ProxyCommand's
`argv[0]` is frequently not a path. It is **appended** to the search list, so
an operator who set `DROPSSH_CA_BUNDLE` keeps the bundle they chose.

**Measured end to end, with a live verified TLS handshake.** A release directory
containing nothing but `dropssh` and `ca-certificates.crt`, with a binary built
so that the system paths were removed from its search list, against
`tcp.ssh.relay.ajam.dev`:

| | result |
| --- | --- |
| bundle present | **TLS verified**, and the failure was the relay's 403 |
| bundle removed | `no CA bundle found ... this build looked there (/tmp/ct2/ca-certificates.crt); if it is not there, the release is incomplete` |

The source is **certifi, pinned by commit** (`9d0a8f1f…`), and not curl's own
bundle, because **curl's repository does not contain one**: `scripts/cacert.pem`,
`certs/cacert.pem` and `scripts/curl-ca-bundle.crt` all return 404 at
`curl-8_11_1`, `curl-8_10_1`, `curl-8_9_1` and `master`. curl links against the
OS store, so "fetch curl's bundle" cannot be done and a build that claimed to
had been shipping whatever the build host happened to have. 121 certificates
in the shipped bundle, and the fetch retries three times because a transient
429 is not a missing file.

## R9. A `--passwd-file` option patched into dropbear

The best remaining change to the product, and it removes the `LD_PRELOAD`
dependency and the glibc/musl split with it. `dropbear` would read its passwd
database from a file, `serve` would not need a shim, and a static server would
become usable. The e2e case: a server with **no** `LD_PRELOAD` in its
environment still authenticates.

