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

**Updated 2026-09-30.** `tests/e2e.sh` is **36/36** (the SOCKS byte path is
case 36, gated 2026-09-30) and `tests/mux-probe.py` carries **fourteen**
cases. The SOCKS forward's last mile is done: the node publishes the session,
sends `ready`, and pumps it, and the relay waits on that `ready` bounded
before answering CONNECT. What follows is the history, kept because the
record of what was tried is what stops the next redesign retrying it.

Four defects were found by writing the cases rather than by reading the code,
and three of them were **silent data loss or a wrong refusal**:

| found by | what it was |
| --- | --- |
| the 300 KB case (#10) | `relay.c` clamped an operator's frame to the node's `maxFrameBytes`, so **300000 bytes arrived as 65536** and 234464 were lost with no close and no log |
| U2's ownership case | `ws_close` NULLed `ws->t` without setting `ws->closed`, so a write on a closed or moved-from session **dereferenced NULL** |
| U2/U3's concurrency read | `NameSlot.node` was a bare pointer **into** a heap `NodeCtx` the node's own thread freed, so a writer used freed memory |
| rebuilding the release | `scripts/build-dropbear.sh`'s idempotency marker was a string in **neither** the patch nor the patched source, so the **second `build.sh --full` in a clean checkout always failed** |

**Updated again the same day.** Six more items closed, each with its own entry:
**R9** (`--passwd-file` patched into dropbear, so a server with **no
`LD_PRELOAD` in its environment** authenticates — measured in the gate), **R7**
(the release ships a CA bundle and the binary finds it beside itself, proven
with a live verified handshake), **R8** (the relay's own document, fetched
with its version, five measured facts re-checked), **R2** (a real-relay session
job, built and needing a credential this repository does not have), **#4/#8** (an
operator-side SOCKS5 that reaches exactly one named destination) and the
ligolo reconnection budget from **#8**.

⛔ **AND THE HALF-DONE ONE IS DONE 2026-09-30, WHICH CORRECTS TWO CLAIMS IN
THIS FILE.** The SOCKS5 listener, its destination policy and the node's side
of the forward were shipped and measured, and the last mile now carries
bytes: the node publishes the SOCKS session, sends `ready`, and pumps it
through the ordinary session path, and the relay waits on that `ready`
bounded (20 s) before answering CONNECT. 3/3 runs, 225 bytes each way
through a live destination, and the case is in the gate
(`tests/socks-forward-test.sh` via `tests/e2e.sh`).

⛔ The `futex_do_wait` diagnosis below was wrong. The node never reached a
mutex at all: the publish path sat inside the ssh-spawn branch, so a SOCKS
session never reached it, never sent `ready`, and the relay's wait was the
only thing that moved. Read the braces before the stacks. The relay half had
a second defect of its own: a raw byte pump wrote into a socketpair where
`client_thread` reads websocket frames, so the first payload parsed as a
frame header. The forward keeps the table entry, the id, the ready gate, the
refcount and the sweep, and drives the bytes with its own two halves. What
was written here about three designs tried stands; what it concluded about a
lock does not, and the paragraph below is kept so the correction is visible.

The node receives an `open` carrying a destination and **dials it**. What was:

⛔ **ONE CLAIM ABOVE IS NOW KNOWN TO BE TOO STRONG, AND IT IS CORRECTED WHERE
IT LIVES.** "U2/U3's concurrency read: a writer used freed memory" states the
defect correctly, but the implicit suggestion that the REFCOUNT is what stops
it is wrong. `node_done` ends with `ws_close(ws)`, so the session's buffers are
freed *before* the connection thread reaches the free, and `ws_write` on the
already-closed session returns -1. Measured: a relay with the refcount removed
served 379 writes across a node's disconnect without a crash. The refcount is
defence in depth; the ORDERING is what holds. See review 3 in
[`relay-issues.md`](relay-issues.md).

What remains from the original list is **nothing but the research issues
that are deliberately not work** (**#3**, **#5**, **#6**, **#7**, **#12**).

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
| **R2** | **DONE, with no credential.** `tests/relay-session.sh` mints its own pair with `POST /v1/pair` and carries a real session, a 270528-byte transfer by sha256, and two sessions alive at once on one node socket. ⛔ This entry previously said it "cannot run here" and needed three repository secrets; that was WRONG, and the relay's own `llms.txt` at r12 says `POST /v1/pair` with an empty body is self-service. Measured against the live relay 2026-09-28. |
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

## R9. A `--passwd-file` option patched into dropbear — DONE 2026-09-28

It was the best remaining change to the product, and it removes the
`LD_PRELOAD` dependency and with it the glibc/musl split. `dropbear -Y FILE`
reads its passwd database from a file, so a server needs no shim — and a static
server becomes a thing to consider rather than a thing the build refuses.

**The e2e case, and it is the one R9 asked for by name: a server with NO
`LD_PRELOAD` in its environment still authenticates.** Measured, in the gate:
a real `ssh` client logs in to a server whose environment contains no shim —
absent, not unset — reading its user from a `passwd(5)` file.

⛔ **AND THE CLIENT IS GIVEN THE SHIM AND THE SERVER IS NOT, BECAUSE THEY ARE
DIFFERENT MACHINES IN THE SAME TEST.** `ssh(1)` on a host with no
`/etc/passwd` cannot map its own uid and refuses to start, so the client needs
one to exist. That is a fact about the sandbox and not about the server under
test, and conflating them produced `No user exists for uid 0` — which is
OpenSSH complaining about the *client*, and names the wrong process entirely.

The parser is at `fill_passwd`, the single point every login passes through,
and in `common-session.c` rather than a new file so the patch touches no
generated `Makefile.in` on a tree pinned by commit. Four things are **refused**
rather than guessed, and the uid is the one worth naming: `atoi` is not used,
because its answer to a non-numeric string is 0 and 0 IS root. A line that is
not seven fields is *skipped* rather than refused, so somebody else's typo
gets a login failure naming the user instead of a refusal they cannot act on.
A line longer than the buffer is refused rather than copied truncated, because
the shell is the last field and a truncated line is a login with a shorter
shell than the file says.

⛔ **AND A STATIC SERVER IS NOT YET USABLE, WHICH THE DOC MUST NOT OVERCLAIM.**
`dropbear` itself is still built dynamic glibc by `build.sh`, and the libc
split still holds for the default path. What R9 removed is the *requirement*
for the shim, not the build's choice: a server can now run with no `LD_PRELOAD`
at all, and a static build is a follow-up that nobody has measured.

