# Relay: bugs and requests, and what happened to each

Every defect and request that concerns the **relay**, its wire protocol, or the
two verbs that speak to it. Pulled out of
[`open-issues.md`](open-issues.md) so the relay work is one list.

## Status, 2026-09-28

**B1 through B10, R1, R3, R4, R5, R6, R10 and R11 are fixed**, in commit
`67308d8` ("serve: one socket, many sessions, and the framing rules that make
it safe"). B11 and B13 are not ours to fix and are now measured; R2 is a
scheduled job and cannot run on every commit.

Each entry below carries, at its head, **what was done and what makes the same
defect mechanically impossible rather than merely absent.** A fix that leaves
the trap armed is not a fix.

**Read [`reverse-relay.md`](reverse-relay.md) first.** The protocol there was
measured live, and the single most important thing in it is that the relay's
two legs are not symmetric: the operator writes bare bytes and the node prefixes
every frame. Half the entries below were consequences of getting that backwards.

**B4 was the root cause of most of the rest**, and it is fixed by structure
rather than by care: `ws.c` has exactly **one** decoder, and `ws_read` (the
byte stream) is defined on top of the same frame queue rather than beside it.
There is no longer a second place where a frame boundary can be got wrong.

B11's claim about the relay was **measured and found wrong**; see its entry.
The relay does not drop a bare node frame in silence, it closes with 1009
`bad multiplex frame`. Five places in this tree repeated the wrong claim and all
five are corrected.

---

# Bugs

## B1. `dropssh serve` handles one session and then disconnects

> **RESOLVED 2026-09-28, commit `67308d8`.** `dropssh_serve` is now a
> multiplexer: it holds one websocket and dispatches frames to a session table
> keyed by the relay's 32-hex id, so N operators are served on one socket.
> **What makes it mechanically impossible:** the node no longer has a code path
> that ends a session, tears down the socket and redials. `src/serve.c` has one
> reader thread that owns the socket for its whole life, and a session is a row
> in a table rather than a call stack. The e2e asserts the socket count directly
> -- `registered with` appears once for two concurrent sessions -- so a change
> that reintroduced one-socket-per-session fails a test rather than being
> noticed by an operator whose second login hangs.


**Where:** `src/serve.c`, `dropssh_serve`.

It takes a session, runs it, then tears down the websocket and redials. A
second operator gets nothing, and the node re-registers in between.

**Looks like:** the relay works, the first login works, and the second one
hangs until a timeout. No error anywhere.

**Blocked on:** B5, which is the same fix.

---

## B2. `dropssh serve` cannot talk to the ajam reverse relay

> **RESOLVED 2026-09-28, commit `67308d8`.** `serve` speaks the relay's
> multiplexed reverse protocol: it prefixes the 32-hex id on every node data
> frame, answers `open` with `ready` within a bound, and reads the bare payload
> the relay strips. **Measured live** against `tcp.ssh.relay.ajam.dev` through
> a 443-only CONNECT proxy: a pubkey session to uid 0, and two concurrent
> sessions on one node socket with a 270177-byte transfer byte for byte.
> **What makes it mechanically impossible:** `tests/mux-probe.py` asserts the
> asymmetry (operator bare in / node bare out), and plants a node frame with no
> id to assert the close is 1009 `bad multiplex frame`. The guard was verified
> to fire by rebuilding with the silent drop restored, and to pass against the
> correct relay. See also the B11 correction below.


**Where:** `src/serve.c`, `src/ws.c`.

The relay's two legs are not symmetric, and `serve` sends bare frames on the
node leg. ⛔ **CORRECTED 2026-09-28:** a bare frame from a node is **not**
discarded without a word. The relay closes the **node's** socket with **1009
`bad multiplex frame`** and the operator with **1011 `node disconnected`**.
The old text asserted silence, from a 2026-09-27 measurement, and an
implementer following it had no way to know 1009 existed.

**Looks like:** `open` arrives, the ssh server starts, the operator connects,
and the session is silent -- but now the node also learns WHY, by close. That
is the difference between a close code and a comment: see B11.

**Blocked on:** B1.

**The measurement, so nobody has to rediscover it.** Four cases in one live
session, 2026-09-27:

```
operator sends bare payload    -> node receives id+payload     (relay PREPENDS)
operator sends id+payload      -> node receives id+id+payload  (doubled)
node sends bare payload        -> node closed 1009, operator closed 1011  (2026-09-28)
node sends id+payload          -> operator receives bare payload (relay STRIPS)
```

So the **operator writes raw bytes with no framing at all**, and the **node
prefixes every frame**. Full transcript in
[`reverse-relay.md`](reverse-relay.md#the-protocol).

---

## B3. `dropssh connect` writes the whole frame to stdout

> **RESOLVED 2026-09-28, commit `67308d8`.** `connect` sends stdin as **bare**
> binary frames on every link, and receives bare payloads from the reverse relay
> (which has already stripped the id). **What makes it mechanically impossible:**
> the id-stripping code does not exist in `connect.c` at all, so there is no
> branch that could be pointed at the wrong leg; and the local relay is asserted
> by `tests/mux-probe.py` case 1, which fails if the operator sees the 32-hex
> id in front of its payload.


**Where:** `src/connect.c`, `dropssh_connect`.

On a multiplexed or forward relay the client must not emit the 32-byte session
id, and this one does not strip it. Thirty-two hex characters in front of
every ssh packet.

**Looks like:** an ssh banner mismatch, or a KEX that fails with a protocol
error naming the wrong layer.

**Why CI is green:** the e2e's local relay does not multiplex, so the
strip path is never reached. This is the same class of failure as B4 and it
is the reason B12 exists.

---

## B4. `ws_read` is a byte stream, not a frame reader

> **RESOLVED 2026-09-28, commit `67308d8`.** `ws.c` now has **one** decoder
> (`decode_available`) feeding a queue of frames that each carry their own
> opcode, and `ws_recv_frame` / `ws_poll_frame` hand out one frame at a time.
> `ws_read`, the byte stream, is defined **on top of** that queue rather than
> beside it, so the forward path cannot observe different framing behaviour.
> **What makes it mechanically impossible:** there is no second decoder in the
> file, and a frame is consumed exactly once when it is delivered (the payload
> is copied into a caller-owned buffer, so it cannot be handed out twice or
> aliased into freed memory). A fragmented message keeps the opcode of its
> **first** frame, not its last, which was the specific coalescing bug recorded
> in `multiplexing.md`.


**Where:** `src/ws.c`, `ws_read`.

It returns "whatever has arrived", not one frame. Any layer that needs message
boundaries is one coalescing bug away, and when two frames arrive together the
opcode reported is the **last** one's for both.

**Looks like:** a control message parsed with session data still attached, or a
text control message demultiplexed as session bytes because a binary frame
arrived after it.

**This is the root cause of B3 and of the class in
[`multiplexing.md`](multiplexing.md).** Fix it first; the rest is cheaper.

**Also worth knowing:** an earlier attempt returned a pointer into the pending
buffer without consuming it, so the same frame was returned forever and the
session was flooded until the client gave up. If a frame reader is added, it
must consume what it returns, and the opcode must travel with its own frame.

---

## B5. Two threads read one socket

> **RESOLVED 2026-09-28, commit `67308d8`.** One reader thread per websocket,
> ever. In `serve.c` the node's reader is `mux_reader` and it is the only thing
> that calls `ws_recv_frame` on that session; session threads touch only their
> own socketpair and their own queue. In `relay.c` each operator's socket is
> read by that operator's own thread, and the node's socket is read by the
> node's thread. **What makes it mechanically impossible:** the per-node write
> lock in the relay, because N operator threads writing the node's socket
> interleaved frame headers with payloads and produced a frame whose length and
> payload disagreed. The lock is per **name**, not global, so two nodes do not
> serialise against each other.


**Where:** `src/serve.c` (session threads and the node read loop),
`src/relay.c` (the node reader and each session's client reader).

A frame can be taken by whichever thread happens to be running, so one session
can receive another's bytes.

**Looks like:** nothing, with one session. It works with one session, which is
exactly what makes it dangerous, and it is why the wire-level tests must cover
**two concurrent sessions** and not one.

**Fix:** one reader per websocket, ever. The reader dispatches to sessions by
id, so a frame has exactly one possible destination.

---

## B6. `dropssh connect` forks

> **RESOLVED 2026-09-28, commit `67308d8`.** `connect` is a single-threaded
> event loop over stdin and the socket: no `fork`, no thread, one mbedTLS
> context used by one thread. **What makes it mechanically impossible:** both
> legs are non-blocking and the loop never blocks, so there is nothing to fork
> for. This also fixed a **live hang** that only reproduced over TLS: the TLS
> read path used to sleep and retry inside `mbed_recv`, so a read that had to be
> non-blocking blocked instead, and the operator received the node's banner,
> opened its ready gate, and then never sent its own. `mbed_recv` now returns
> `MBEDTLS_ERR_SSL_WANT_READ` and the caller's loop owns the waiting.


**Where:** `src/connect.c`.

`fork()` copies the mbedTLS context, not just the descriptors, so a child
writing while the parent reads corrupts the record layer.

**Looks like:** `could not write to the relay` from the child, on a connection
and a network that are both fine.

**Fix:** one process, one event loop over stdin and the socket. There is no
thread either, because a thread would share the context legitimately and
mbedTLS's read and write are not concurrent-safe on one context.

---

## B7. No backpressure anywhere

> **RESOLVED 2026-09-28, commit `67308d8`.** `ws_write` chunks at the relay's
> advertised `maxFrameBytes` (read from its `hello`, not hardcoded), the
> decoded-frame queue is bounded (`ws_set_queue_cap`) and a peer that overruns
> it has the session closed rather than being allowed to choose this process's
> allocation, and the node refuses to open more than the relay's `maxSessions`
> -- it answers `reject{id,reason}` instead. **What makes it mechanically
> impossible:** the advertised limits are now policy numbers enforced where the
> frames are built, so a relay cannot close us for exceeding a limit we agreed
> to, and an operator reading the log sees `at its N session limit` rather than
> a hang.


**Where:** all three verbs.

A fast peer and a slow one fill the socket until one of them dies. Nothing
reads ahead, nothing bounds an in-flight queue, and there is no point at which
a client is told to slow down.

**Not honoured:** `maxFrameBytes: 65536` and `maxSessions: 64`, both of which
the relay states in its `hello` frame and both of which `serve` ignores.

**Fix:** bounded queues with a documented overflow behaviour, and the two
advertised limits enforced as policy numbers rather than as hints.

---

## B8. There is no way to ask a relay what it is doing

> **RESOLVED 2026-09-28, commit `67308d8`.** `dropssh relay --status` prints
> peers, limits, sessions, bytes and upgrade counters, read under the same lock
> the writers take. **What makes it mechanically impossible:** the counts are
> incremented at the event, not computed on demand, and none of them is a
> literal. (The original claim that `--status` existed and printed a hardcoded
> 32 was wrong and is corrected here; it did not exist at all.)


**Where:** `src/relay.c`, `src/serve.c`.

Neither verb has a status or a query mode. `dropssh relay` prints one line when
it starts listening and then nothing; `dropssh serve` prints a line when it
registers. There is no way to ask, from anywhere, how many nodes are connected,
how many sessions are open, how many bytes have moved, or when a node was last
seen.

**Looks like:** a relay you cannot debug without attaching a debugger to it.
Every question about a live relay is answered by adding a trace and rebuilding,
which is slow and tells you about the build rather than about the relay.

**Related:** an earlier draft of this file claimed `dropssh relay --status`
exists and prints a hardcoded `32`. **It does not exist at all**; the claim was
written from memory of a discarded draft and was wrong. Corrected here rather
than shipped, because a bug list with a bug in it is worse than a shorter one.

---

## B9. `dropssh relay` has no limits and one session

> **RESOLVED 2026-09-28, commit `67308d8`.** `--max-peers`, `--max-sessions` and
> `--idle-timeout` are enforced at upgrade time and printed at startup, and the
> relay now serves many sessions on one node socket. **What makes it
> impossible:** the peer cap is checked after the upgrade headers and refused
> with a **named** 503 before any pairing, so a turned-away peer can tell a full
> relay from a broken one.


**Where:** `src/relay.c`.

No peer cap, no idle timeout, no handshake rate limit, and a single operator at
a time.

**Looks like:** a locally trivial denial of service, and a relay that
accumulates half-open sessions.

**Fix:** peer and session caps as policy numbers, an idle timeout on both, and
a bound on the handshake rate.

---

## B10. The e2e never touches the forward path or a real relay

> **PARTIALLY RESOLVED 2026-09-28, commit `67308d8`.** The e2e now carries
> **two concurrent sessions on one multiplexed relay** with cross-checks, and
> `tests/mux-probe.py` covers the forward/reverse framing split without a
> network. **Still open:** the real-relay CI job (R2), because it needs a
> credential and a network and cannot run on every commit. What was done
> instead is that the framing rules R2 would have guarded are now asserted
> locally, and the live path was **measured by hand** on 2026-09-28 (two
> concurrent sessions, 270177 bytes) rather than left to be discovered by a
> user.


**Where:** `tests/e2e.sh`.

Zero occurrences of `mint` or `/connect/`. Every session case runs against the
in-process local relay.

**Consequence:** B3, B6 and B9 are all invisible to the gate. They were found
by hand, and hand verification is not a gate.

**Fix:** a `tests/relay-e2e.sh` that takes a relay URL and a token and drives a
real session through `connect --mint`. It cannot run on every commit because it
needs the network and a token, so it belongs in a scheduled job.

---

## B11. The relay drops a bare node frame without saying so

> **MEASURED 2026-09-28: THE CLAIM IS WRONG, AND OUR RELAY NOW MATCHES.** This
> entry, and four other places in this tree, said a node frame without the id
> is silently discarded. Re-measured against the live relay, 3/3 runs: the
> **node** socket is closed with **1009 `bad multiplex frame`** and the operator
> is then closed with **1011 `node disconnected`**. The requirement is unchanged
> and the asymmetry is unchanged; what is new is that the failure is loud and
> named. We cannot say the relay *changed* -- the original measurement is from
> 2026-09-27 and there is no instrumented run from that day -- so the honest
> statement is that the old document and the live relay disagreed. **What makes
> it mechanically impossible to repeat the mistake:** `tests/mux-probe.py`
> asserts the 1009 close on our own relay, and `mux-probe.py` was verified to
> fail when the silent drop is planted, so the claim is in a test and not in
> prose.


**Where:** the relay, not this repository.

A node that omits the id prefix has its socket closed with 1009
`bad multiplex frame`. ⛔ **This entry said "silently discarded: no error, no
close, and the session goes quiet". That is wrong, and it is corrected at the
head of this entry; see the measurement there.

**Why it matters here:** it is B2's failure mode, and it is the most expensive
kind, because a node that omits the prefix looks like a relay that is not
working. A close frame carrying a reason would turn an afternoon into a minute.

---

## B12. The relay rewrites a bogus operator id instead of rejecting it

**Where:** the relay.

An operator frame carrying `"f"*32 + payload` arrives at the node as
`<real id> + payload`: the id is replaced and the payload kept.

**Not exploitable.** Tokens are scoped per pair and per role, and the far end
must already be on the node's socket, so there is no cross-session path today.

**Consequence for a client:** the id in an operator frame is **ignored** and
must not be treated as addressing. A client that relies on it to route will be
wrong in a way that only shows up when a second session exists.

---

## B13. The reference operator inverts text and binary

**Where:** `docs/08-reverse.md` in the relay's repository, as pasted on
2026-09-27.

`if (typeof e.data !== "string")` is backwards. A string **is** a control
message, so as written a binary frame's `typeof` of `"object"` also enters that
branch, goes through `JSON.parse`, throws, and calls `fail()`.

**Looks like:** every session dies on the first data frame, with an
"unexpected text" message that names ssh bytes.

**Fix:** `if (typeof e.data === "string")` for the control branch.

---

## B14. The reference operator does not parse

**Where:** the same file, same paste.

```javascript
process.stdin.on("end", () => { closing = true; try { ws.close(); } catch {} setTimeout(() => process.exit(0, 3000); });
```

`setTimeout(() => process.exit(0, 3000);` is missing a `)`. Verified with
`node --check`: `SyntaxError: missing ) after argument list`.

**The instructions do not balance.** The prose says to delete the `setTimeout`
line for sessions over a minute, which only works if the line is repaired
first:

```javascript
process.stdin.on("end", () => { closing = true; try { ws.close(); } catch {} process.exit(0); });
```

**Also worth changing if the file is kept:** it exits 0 on any close, which
discards the relay's close reason. `node open timeout` and `binary frames
required` are the diagnosis, and both are lost.

---

# Requested: features and quality of life

Ordered by how much they would have helped on 2026-09-27.

---

# Requests

## R1. A framing probe as a script in the repository

> **RESOLVED 2026-09-28, commit `67308d8`.** `tests/mux-probe.py` is it. It
> starts a real relay, drives a node and an operator against it, and prints
> what each side observed. It needs no network and no token, so it runs on
> every commit, which is the thing R1 was really for.


**The single most useful thing on this list.** I established the wire format
three separate times today and got it wrong twice, in opposite directions,
with a wrong document committed both times. The measurement was sound each
time; the *inference* was not, because a claim taken on one leg and generalised
to two is not a measurement.

`tests/relay-probe.c`, taking a base URL and a token, that opens a pair and
prints the four-way table above plus the auth matrix. It is an hour of work and
it removes the largest source of error in this project so far.

## R2. Run the verbs against a real relay in CI

`connect --mint` against a public target, on a schedule rather than every
commit. This is the gate that would have caught B3, B6 and B9.

## R3. `dropssh doctor`

> **RESOLVED 2026-09-28, commit `67308d8`.** `dropssh doctor` reports the uid,
> whether `bind(2)` works on loopback, `/dev/ptmx`, `/etc/passwd`, name
> resolution, the egress proxy, TLS verification, whether the server command
> stays up on a socketpair, and relay reachability by route. It exits non-zero
> on a failed check. **What makes it mechanically impossible to guess:** each
> check reads rather than infers -- in particular `bind(2)` is **probed**, not
> inferred from uid, because the reference cage is bindless at uid 0.


Report, without guessing: the uid; whether a passwd database is reachable and
through what; the CA bundle in use; whether the server command starts; relay
reachability by route; the dropssh, dropbear and sandhome versions; and whether
`POST /v1/pair` succeeds from here.

Half of today's failures were environment questions answered by guessing. A
doctor turns each into one line.

## R4. `--json` is a dead flag

> **RESOLVED 2026-09-28, commit `67308d8`.** `--json` now selects a real event
> stream (`src/events.c`) on **stderr**; stdout is left clean because on the
> connect verb it is ssh's byte pipe. The e2e asserts both halves: a
> `"event":"start"` line appears, and stdout stays free of it. **What makes it
> mechanically impossible to be a dead flag again:** the mode is decided once in
> `events_set_json` and every event goes through one function, so there is no
> second path that could ignore it.


**Where:** `src/main.c:171`.

`--json` is accepted, sets `o.json`, and **nothing ever reads it**. No verb
emits a machine-readable line. A flag that is accepted and ignored is worse
than one that is refused, because an operator who passes it believes they have
machine-readable output.

**The events wanted,** on stderr so stdout stays a clean byte pipe:
`registered`, `session_open`, `session_close` with bytes in and out and
duration, `refused` with the reason, `reconnect` with the backoff, `pair` with
the name and the expiry.

Today a failure is one human sentence, and answering the next question means
adding a trace and rebuilding.

## R5. `dropssh pair`

> **RESOLVED 2026-09-28, commit `67308d8`.** `dropssh pair --relay HOST` POSTs
> `/v1/pair` and prints the name, the node token and the connect token, ready to
> paste, so a token never lands in shell history. **What makes it mechanically
> impossible to get the roles wrong:** the reverse `/v1/pair` endpoint is used,
> not the forward `/v1/mint`, so the two lines carry genuinely **different**
> tokens. (The first version built `pair` on `mint` and printed the same forward
> token twice under two role labels, which looked right and was refused 403 on
> the node upgrade.)


Print a ready-to-paste node token and connect token. Today the operator runs
curl, and the token lands in shell history.

## R6. A `dropssh config` that prints the resolved settings

> **RESOLVED 2026-09-28, commit `67308d8`.** `dropssh config` prints every
> setting and its source (flag / environment / built-in), and never prints a
> token's value. **What makes it mechanically impossible to leak a credential
> by asking for the config:** the token line reports `(set, not printed)` and the
> e2e asserts the value is absent even when a token is supplied.


Every option, every default, and where each value came from: flag, environment
or built-in. A wrong setting discovered by reading the resolved output is a
class of report that otherwise arrives as "it ignored my flag".

## R8. Fetch `docs/08-reverse.md` from the relay, pinned

The reference implementation next to ours, so drift is visible rather than
discovered. The shims are fetched this way already; the protocol reference
should be too.

## R10. Two **concurrent** sessions in the e2e

> **RESOLVED 2026-09-28, commit `67308d8`.** `tests/e2e.sh` launches two ssh
> sessions at once against one node, one of which sleeps 4s while the other
> runs a 270 KB transfer, then cross-checks that neither saw the other's marker.
> The node's own log is then read to assert `registered with` appears **once**
> for **two** sessions. **What makes it mechanically impossible to pass with a
> one-socket-per-session implementation:** that count is a direct measurement of
> the property, not a proxy for it.


**Where:** `tests/e2e.sh:298`.

There is a `session2` case and it is **sequential**: it runs after `session1`
has finished. One session cannot catch B5, because the race needs two
simultaneously.

**The case wanted:** two operators at once against one node, interleaved
traffic, each receiving only its own bytes, plus a check that a frame for one
session never appears in the other's stream. That is what makes the
multiplexer trustworthy rather than apparently working.

## R11. A negative test for the id-prefix rule

> **RESOLVED 2026-09-28, commit `67308d8`.** `tests/mux-probe.py` is the test.
> It asserts the positive case (node id-prefixed frame reaches the operator
> bare; operator bare frame reaches the node as id+payload) and the negative
> case (a bare node frame is closed 1009, not silently dropped), plus the 1003
> close for a text frame on a data leg. **What makes it mechanically
> impossible:** the guard was proven to fire by planting the defect.


Send a bare frame from a node and assert the operator receives nothing, and
send an id-prefixed frame and assert the payload arrives bare. It pins the
asymmetry in the gate rather than in a document, so a future change to either
side of it is caught by a test instead of by an afternoon.

---

# ⛔ KNOWN-UNGUARDED: three, and the list is here so it cannot be lost

> **U1 IS NOW CLOSED**; its full entry, with the plant counts, is at the very
> end of this file. **U2 and U3 remain 0/6.**

**2026-09-28, after a five-pass review of `d986214`.** Six defects were
planted — built, run, and counted — and three came back **0/6**. A guard that
has never been seen to refuse is not a guard, so these are recorded here with
what would be needed to close each. ⛔ **This list exists because two sessions
wrote "every guard was proven to fire" and were wrong, and the cost of that is
a commit message asserting something is safe when it is not.**

| # | what | why 0/6 | what would close it |
| --- | --- | --- | --- |
| **U1** ✅ | the 60-second bound on the `ready` wait, `src/connect.c` | unreachable: this relay answers **503 on the upgrade** for a name with no node, so nothing reaches the bound | **CLOSED 2026-09-28.** A relay **stub** in `tests/mux-probe.py` that completes the operator's upgrade, speaks the real protocol, and then says nothing. The bound is now a value the binary itself reports (`--bound-ms`, printed in `connect --help`), so its absence is measurable. See U1's own entry at the end of this file. |
| **U2** | the session **move** in `src/relay.c` (`c->ws = ws; memset(&ws, ...)` rather than a `memcpy`) | unreachable: every `ws_close(&ws)` on the operator path is *above* the move, so a copy aliases nothing that is later closed | a refusal path **below** the move. It is defence in depth — one owner per session, established where the session is stored — and a future refusal added there would reintroduce the aliasing silently |
| **U3** | the 1011 sweep in `src/relay.c` with no reference held | the window is narrower than 6 probe runs; case 4 forces the ordering but does not land inside it | a case that closes an operator and drops its last reference **in the same instant**. May need a fault-injection hook rather than a timing trick |

**The three that ARE guarded, with the counts, so the shape of a real guard sits
next to the three that are not:**

| plant | caught |
| --- | --- |
| silent drop (B11) | 6/6 |
| id not stripped (B3) | 6/6 |
| no early-data refusal | 6/6 |
| no bound on the `ready` wait | **0/6, then 3/3** (U1, closed) |
| aliased session owner | **0/6** |
| 1011 sweep with no refcount | **0/6** |

⭐ **And one more that is not a plant but is the same disease.** The framing
probe once passed for several runs while its node had **stopped** answering
`open` with `ready` — because the relay did not enforce the ordering, so the
probe was asserting that the relay does **not** require `ready`, the opposite of
what it claimed. A test that passes for the wrong reason is worse than one that
fails, and the check is cheap: ⛔ **does the plant make the thing this case
claims to test actually change?**

---

# U1, closed: the bound on the `ready` wait is now guarded

**Done 2026-09-28.** U1 was the one on this list a stub could reach, and it is
now reached.

**What changed in the product.** The wait for a node's `ready` is bounded by
`o->bound_ms` rather than a literal. Its default, `DROPSSH_READY_BOUND_MS`, is
60000 ms, lives in `src/dropssh.h` so `main.c` can print the same number the
loop uses, and `--bound-ms N` overrides it. `connect --help` prints
`Default is 60000 ms`, and `0` means **no bound at all** and produces a
different sentence, so a build that has lost the bound cannot be mistaken for a
working one by reading its output.

**Why a stub and not `dropssh relay`.** The reason U1 was 0/6 is now stated
correctly: not that the bound is unreachable, but that **this** relay is
unreachable *for* the bound. `dropssh relay` answers 503 on the upgrade for a
name with no node, and the live ajam relay holds the operator and then closes
1008 `node open timeout` at about ten seconds. Both end the session long before
a 60 s client-side bound, so both measure the RELAY's patience, not the
CLIENT's. The bound exists for the relay that never closes, so the fixture has
to be one that never closes: `SilentNodeRelay` in `tests/mux-probe.py`
completes the WebSocket upgrade, verifies `Sec-WebSocket-Accept`, sends `hello`
and then `open`, and then reads and discards for ever.

⛔ **THE STUB SPEAKS THE PROTOCOL, NOT JUST THE SILENCE.** A fixture that only
completed the upgrade would be a socket that is not a relay at all, and a bound
that fired there would say nothing about a bound firing on a relay. It sends
the two control frames a real relay sends, so `connect` is genuinely waiting for
a `ready` from a node that has been asked and has not answered.

**The counts.**

| build | what it is | case result |
| --- | --- | --- |
| correct | bound 60000 ms | **passes**; 6/6 then 3/3 across two rounds, wait measured 60.0 s each time, exit 1, message names `ready` and not `1008` |
| `DROPSSH_READY_BOUND_MS 0` | the option exists, the bound is gone | **3/3 caught**: exits after 0.0 s, having given up on a `ready` that had not had time to arrive |
| the `if (waited_ready >= ...)` block deleted | the bound is not evaluated | **3/3 caught**: no return within 180 s |

**⛔ THE CASE WAS WRONG TWICE BEFORE IT WAS RIGHT, AND IT WAS GREEN BOTH TIMES.**
Recorded because this is the failure mode this repository has now hit four
times, and because a reader deciding whether to trust the case above needs to
know it was green while wrong.

1. **The first version used the real relay.** It measured the relay's 1008
   close, not the client's bound, and passed for that reason. Same trap as case
   6, which is still asserted separately for the 503 path because it is a real
   operator situation and a real half of the behaviour.
2. **The parse that reads the bound out of `--help` matched nothing and fell
   back to 60000.** On the correct build the fallback is the right number, so
   the case passed; on a zero-bound build it was the wrong number and the case
   failed in the branch written for a working bound. The help text was then
   reworded so the number is unambiguous, and the probe now reads the sentence
   the help actually prints and treats a build that prints no such sentence as a
   **failure**. ⛔ A fallback that happens to equal the correct answer is
   invisible exactly when the thing it stands in for is right.

**What this does not establish.** The stub covers one relay misbehaviour: the
one that never closes. The live relay's own ten-second close is a different
path, covered by case 6. Nothing here measures a node that is slow rather than
absent, and R2, the scheduled real-relay job, is still the only thing that
would.

# Not in this list

Two entries in [`open-issues.md`](open-issues.md) are about the ssh server
rather than the relay and are deliberately excluded here:

* **R7**, ship the CA bundle in the release. The bundle is fetched at build
  time for mbedTLS and discarded, so a clean machine has none. It affects every
  TLS connection, forward and reverse alike.
* **R9**, a `--passwd-file` option patched into dropbear. It removes the
  `LD_PRELOAD` dependency and the glibc/musl split, and it is the best remaining
  change to the product. It is a server change, not a transport one.
