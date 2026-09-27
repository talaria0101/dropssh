# Relay: open bugs and requests

Every outstanding defect and request that concerns the **relay**, its wire
protocol, or the two verbs that speak to it. Pulled out of
[`open-issues.md`](open-issues.md) so the relay work is one list.

Date: 2026-09-27. Nothing here is fixed. The tree is at one commit, CI green on
11 jobs, `tests/e2e.sh` 9/9 — and those 9 cases cover **none** of B1 to B10,
which is itself B10.

**Read [`reverse-relay.md`](reverse-relay.md) first.** The protocol there was
measured live, and the single most important thing in it is that the relay's
two legs are not symmetric: the operator writes bare bytes and the node prefixes
every frame. Half the entries below are consequences of getting that backwards.

**B4 is the root cause of most of the rest.** `ws_read` returns a byte stream
rather than one frame, so any layer that needs message boundaries is one
coalescing bug away, and when two frames arrive together the opcode reported
is the last one's for both. Fixing it first makes B3 and the rest of the
multiplexer work cheaper.

Two entries are not ours and are reported rather than fixed: **B11** and **B12**
are in the relay, and **B13** and **B14** are in the relay author's own
reference operator.

---

# Bugs

## B1. `dropssh serve` handles one session and then disconnects

**Where:** `src/serve.c`, `dropssh_serve`.

It takes a session, runs it, then tears down the websocket and redials. A
second operator gets nothing, and the node re-registers in between.

**Looks like:** the relay works, the first login works, and the second one
hangs until a timeout. No error anywhere.

**Blocked on:** B5, which is the same fix.

---

## B2. `dropssh serve` cannot talk to the ajam reverse relay

**Where:** `src/serve.c`, `src/ws.c`.

The relay's two legs are not symmetric, and `serve` sends bare frames on the
node leg. A bare frame from a node is **silently dropped**.

**Looks like:** `open` arrives, the ssh server starts, the operator connects,
and the session is completely silent. Same as every other framing bug, and
this is the framing bug.

**Blocked on:** B1.

**The measurement, so nobody has to rediscover it.** Four cases in one live
session, 2026-09-27:

```
operator sends bare payload    -> node receives id+payload     (relay PREPENDS)
operator sends id+payload      -> node receives id+id+payload  (doubled)
node sends bare payload        -> operator receives NOTHING    (silently dropped)
node sends id+payload          -> operator receives bare payload (relay STRIPS)
```

So the **operator writes raw bytes with no framing at all**, and the **node
prefixes every frame**. Full transcript in
[`reverse-relay.md`](reverse-relay.md#the-protocol).

---

## B3. `dropssh connect` writes the whole frame to stdout

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

**Where:** `src/relay.c`.

No peer cap, no idle timeout, no handshake rate limit, and a single operator at
a time.

**Looks like:** a locally trivial denial of service, and a relay that
accumulates half-open sessions.

**Fix:** peer and session caps as policy numbers, an idle timeout on both, and
a bound on the handshake rate.

---

## B10. The e2e never touches the forward path or a real relay

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

**Where:** the relay, not this repository.

A node that omits the id prefix has its frames silently discarded: no error, no
close, and the session goes quiet.

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

Report, without guessing: the uid; whether a passwd database is reachable and
through what; the CA bundle in use; whether the server command starts; relay
reachability by route; the dropssh, dropbear and sandhome versions; and whether
`POST /v1/pair` succeeds from here.

Half of today's failures were environment questions answered by guessing. A
doctor turns each into one line.

## R4. `--json` is a dead flag

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

Print a ready-to-paste node token and connect token. Today the operator runs
curl, and the token lands in shell history.

## R6. A `dropssh config` that prints the resolved settings

Every option, every default, and where each value came from: flag, environment
or built-in. A wrong setting discovered by reading the resolved output is a
class of report that otherwise arrives as "it ignored my flag".

## R8. Fetch `docs/08-reverse.md` from the relay, pinned

The reference implementation next to ours, so drift is visible rather than
discovered. The shims are fetched this way already; the protocol reference
should be too.

## R10. Two **concurrent** sessions in the e2e

**Where:** `tests/e2e.sh:298`.

There is a `session2` case and it is **sequential**: it runs after `session1`
has finished. One session cannot catch B5, because the race needs two
simultaneously.

**The case wanted:** two operators at once against one node, interleaved
traffic, each receiving only its own bytes, plus a check that a frame for one
session never appears in the other's stream. That is what makes the
multiplexer trustworthy rather than apparently working.

## R11. A negative test for the id-prefix rule

Send a bare frame from a node and assert the operator receives nothing, and
send an id-prefixed frame and assert the payload arrives bare. It pins the
asymmetry in the gate rather than in a document, so a future change to either
side of it is caught by a test instead of by an afternoon.

---

# Not in this list

Two entries in [`open-issues.md`](open-issues.md) are about the ssh server
rather than the relay and are deliberately excluded here:

* **R7**, ship the CA bundle in the release. The bundle is fetched at build
  time for mbedTLS and discarded, so a clean machine has none. It affects every
  TLS connection, forward and reverse alike.
* **R9**, a `--passwd-file` option patched into dropbear. It removes the
  `LD_PRELOAD` dependency and the glibc/musl split, and it is the best remaining
  change to the product. It is a server change, not a transport one.
