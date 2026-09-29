# Relay: bugs and requests, and what happened to each

Every defect and request that concerns the **relay**, its wire protocol, or the
two verbs that speak to it. Pulled out of
[`open-issues.md`](open-issues.md) so the relay work is one list.

## Status, 2026-09-28

**B1 through B10, R1, R3, R4, R5, R6, R10 and R11 are fixed**, in commit
`67308d8` ("serve: one socket, many sessions, and the framing rules that make
it safe"). B11 and B13 are not ours to fix and are now measured; R2 is a
scheduled job and cannot run on every commit.

### The relay answered issue #9, and three of our numbers were wrong

The relay's author replied on 2026-09-28 against a deployed tree at version
`2026-09-28-r11`, having read our measurements. That reply fixed A1 on their
side and answered the open questions, and re-reading it against the live relay
found **three claims in this tree that r11 falsifies**. All three are corrected
in place and the corrections are measured, not taken from the comment:

| our claim | r11 | what we did |
| --- | --- | --- |
| an unanswered `open` closes **1008** at **10 s** | ⛔ **1013 `node open timeout` at 15 s** | measured 15.3 s against the live relay; `src/connect.c` now handles 1013 and 1008 as **different** faults, and `tests/mux-probe.py` case 8 asserts the distinction rather than substring-matching "1008" |
| "the relay's keepalive arrives every 25 s" on the operator leg | ⛔ **there is no application keepalive on the reverse path at all**; 25 s is the FORWARD path's zero-length frame. Quiet is healthy. | a comment in `src/connect.c` corrected; nothing in the code depended on it |
| the operator leg was a "bare byte pipe" with no control frames to parse | the operator **receives** text control frames, including a node's `reject{id,reason}` (A1, new in r11) | `dropssh connect` now **reads** `reject` and reports the node's own reason, exit non-zero. Measured live: `the node refused the session: this node is at its 64 session limit` in 0.4 s. Before this, a refused node gave an open, idle session and no explanation — the exact gap we asked r11 to close on their side, and it is ours to close on ours. |

Two further answers need **no code change** because our reading was already
right, which is worth recording: `maxFrameBytes` does **not** count the 32-hex
prefix (node wire ≤ 65568), which is what `src/serve.c` already enforces; and
B12's id-rewrite is confirmed as an intended contract, not a defect.

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

> **CONFIRMED AS INTENDED, 2026-09-28 (relay r11), and the consequence for a
> client is unchanged.** The relay's author states the behaviour in its own
> published protocol: *"An id an operator sends is rewritten, not honoured, so a
> client must never treat a 32-byte prefix as addressing."* It is a contract,
> not a defect, and `dropssh connect` already obeys it by writing **bare**
> frames on the operator leg. No code change; this entry stays because the
> consequence is the part a future implementer needs.

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

> **PARTLY ANSWERED, 2026-09-28 (relay r11).** Our side asked for the RULE to be
> stated (issue #9, item A2) and the relay now publishes it in the protocol: the
> operator receives text control frames and sends binary data frames only, and
> an operator text frame closes the socket 1003. The author's reply also
> corrects our reading of the pasted file: the reference doc describes the
> **node** sending `ready`, not the operator, and a node's `ready` is never
> silently ignored. ⛔ **We have not re-read `docs/08-reverse.md` in r11, so
> whether the two fatal defects below are fixed in the file is NOT established
> here.** B14 in particular is a syntax error in a paste, and only running the
> current file answers it. Treat both as open until someone runs the published
> client.

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

## R2. Run the verbs against a real relay in CI -- BUILT, needs a credential

`connect --mint` against a public target, on a schedule rather than every
commit. This is the gate that would have caught B3, B6 and B9.

**Done as far as it can be done here, 2026-09-28.** `tests/relay-session.sh`
carries a real session: a pubkey login to uid 0 through a real `ssh` client, a
270 KB transfer asserted by sha256, two concurrent sessions on one node socket,
and the node's own registration count read from its log. A scheduled job runs it.

⛔ **AND IT CANNOT RUN WITHOUT A PAIR, AND THE JOB SAYS SO INSTEAD OF PASSING.**
A pair is minted by the relay's `POST /v1/pair`; the node and connect tokens are
per-pair **and per-role**, and there is no way to obtain one from the outside.
`--mint` is the FORWARD endpoint and answers 403 on a reverse upgrade, measured.
So the job needs three repository secrets, and **a pair expires** — a secret set
months ago is a job that has been quietly measuring nothing. The job reports
three outcomes and never conflates them: ran and passed, ran and failed, or
could not run because no secret is set, which is yellow and states that a green
tick there is not a pass.

⛔ **AND IT NAMES WHICH FAULT IT WAS**, because "connection failed" is the
message that costs an afternoon. 403 on an upgrade is a token or a role problem
and says so; 409 is a name another node holds and says so; a connection error is
the relay or the egress and says so; silence with no error is a credential the
relay never saw. Measured against the live relay with a deliberately wrong
token: the diagnostic arrives in **4 s** and names the token/role case. Without
`--retry-budget 2` the same diagnostic took 60 s and appeared once under nine
copies of itself.

The relay's `/health` is fetched whether or not the credential is present,
because it is the one measurement here that needs no credential and it says
whether the other half is even meaningful.

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

## R8. Fetch the relay's own document, with its version -- DONE 2026-09-28

The reference implementation next to ours, so drift is visible rather than
discovered. The shims are fetched this way already; the protocol reference
should be too.

⛔ **AND A GIT PIN IS THE WRONG SHAPE, WHICH IS WHY IT IS DONE DIFFERENTLY.**
Reading the relay's reply on issue #9 shows there is no repository in this
project to pin: the relay publishes a Cloudflare Worker, and what it SERVES at
`tcp.ssh.relay.ajam.dev` is the thing a client actually talks to. A pin against
a repository records what the source said on a day; this records what the
deployment is serving now, **with its version**, which is the thing that changes.

⛔ **AND DRIFT HAS ALREADY HAPPENED, which is the argument for fetching at all.**
`/health` reported `2026-09-28-r11` when this project's measurements were taken
and `2026-09-28-r12` when the fetch script was written, the same day. **A2** —
"the operator's leg is data-only" — was added between them, in response to our
own issue. Nothing in this tree would have noticed: our client already works
around it by never sending control on that leg, so a protocol change is
invisible here until it becomes a close code in the field.

`scripts/fetch-relay-spec.sh` fetches `llms-full.txt`, `index.md` and
`/health`, writes `docs/relay-spec/` with the version and the fetch time, and
re-checks the **five facts this tree measured**: the two reverse paths, 1009
`bad multiplex frame`, 1003 `binary frames required`, and `node open timeout`.
At `2026-09-28-r12`, **5/5 hold**.

⛔ **IT IS NOT A CONFORMANCE SUITE AND SAYS SO.** Nothing parses the document.
Parsing a peer's prose specification and asserting our client against it would
be a suite we would have to keep correct when the peer rewords a sentence, and a
reword is not a protocol change. The drift path is a report with exit 1 and an
explanation; it was exercised against a document with two facts removed and gave
2 DRIFT lines naming them.

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

> **U1 IS CLOSED**; its full entry, with the plant counts, is at the very
> end of this file. **U2 and U3 are now closed too, and U3's closure CORRECTS
> the claim below.**

**2026-09-28, after a five-pass review of `d986214`.** Six defects were
planted — built, run, and counted — and three came back **0/6**. A guard that
has never been seen to refuse is not a guard, so these are recorded here with
what would be needed to close each. ⛔ **This list exists because two sessions
wrote "every guard was proven to fire" and were wrong, and the cost of that is
a commit message asserting something is safe when it is not.**

| # | what | why 0/6 | what would close it |
| --- | --- | --- | --- |
| **U1** ✅ | the 60-second bound on the `ready` wait, `src/connect.c` | unreachable: this relay answers **503 on the upgrade** for a name with no node, so nothing reaches the bound | **CLOSED 2026-09-28.** A relay **stub** in `tests/mux-probe.py` that completes the operator's upgrade, speaks the real protocol, and then says nothing. The bound is now a value the binary itself reports (`--bound-ms`, printed in `connect --help`), so its absence is measurable. See U1's own entry at the end of this file. |
| **U2** ✅ | the session **move** in `src/relay.c` (`c->ws = ws; memset(&ws, ...)` rather than a `memcpy`) | unreachable: every `ws_close(&ws)` on the operator path is *above* the move, so a copy aliases nothing that is later closed | **CLOSED 2026-09-28.** `ws_move()` in `src/ws.c`, and `tests/wsmove-test.c` asserts the contract on the real `ws.c`. The plant fails 4 named assertions. See the full entry at the end of this file. |
| **U3** ✅ | the 1011 sweep in `src/relay.c` with no reference held | ⛔ **THE STATED REASON WAS TOO STRONG, AND THIS ENTRY IS THE CORRECTION.** See the full entry at the end of this file. | **CLOSED 2026-09-28.** `tests/mux-probe.py` case 10, **25/25 against the original code**, no fault injection needed. |

**The three that ARE guarded, with the counts, so the shape of a real guard sits
next to the three that are not:**

| plant | caught |
| --- | --- |
| silent drop (B11) | 6/6 |
| id not stripped (B3) | 6/6 |
| no early-data refusal | 6/6 |
| no bound on the `ready` wait | **0/6, then 3/3** (U1, closed) |
| aliased session owner | **0/6, then 4/4 by name** (U2, closed; a new instrument, not a new scenario) |
| 1011 sweep with no refcount | **0/6, then 25/25** (U3, closed; **the original 0/6 was measured against the wrong scenario**) |

⭐ **And one more that is not a plant but is the same disease.** The framing
probe once passed for several runs while its node had **stopped** answering
`open` with `ready` — because the relay did not enforce the ordering, so the
probe was asserting that the relay does **not** require `ready`, the opposite of
what it claimed. A test that passes for the wrong reason is worse than one that
fails, and the check is cheap: ⛔ **does the plant make the thing this case
claims to test actually change?**

---

# Five deep reviews: what has been run, and what each one found

**Reviews are not a formality here, and the project's own history is the
argument for them.** The last full pass found a use-after-free, unbounded
fragment reassembly, a refused login reported as success, an aliased session
owner, a deadlock, a test passing for the wrong reason, and a turn-counter that
printed "60s" in five milliseconds. Reading the code finds none of those.

Each review states what was swept and what would have had to be true for it to
fire. An empty result beats an invented one.

| # | angle | over | ran | found |
| --- | --- | --- | --- | --- |
| 1 | correctness, line by line, and the error paths | `f02ae10` + `c9840e0` | read every changed line; exercised every new error path by running the binary | **2 defects**, both fixed |
| 2 | concurrency: what is freed under a pointer, what is written under a lock that can block | `f02ae10` + `c9840e0` | traced every writer and reader of the two structures the commits touch; ran the loop's bound directly against a hostile input | **0 defects in this work**; 1 pre-existing area re-confirmed (U2/U3) |
| 3 | the tests: would each fail if its defect returned? | **every guard added or changed this session, planted and run: `tests/plant-matrix.sh`** | 13 of 15 rows go red. U1 3/3, U2 4/4 named, U3 25/25, and 11 more. ⛔ **Two rows do not go red and are recorded as unreachable rather than passing** -- see the two entries below. **Two guards were MISSING and had to be written** |
| 4 | the docs and the issue comments: does any assert what this change made false? | **every number, status, capability and mechanism claim this session changed** | **3 found and corrected:** the refcount was described as load-bearing when the ORDERING is; "What remains is R9" survived R9 being done; the case count was stale twice. Plus the U3 "0/6" correction from the earlier pass. See the review 4 entry |
| 5 | what is NOT covered, as what was swept and what would have had to be true | **the whole session's work, listed as NOT established** | 6 things, and the one that matters: ⛔ **no sanitizer was run, because there is none on this machine.** Reviews 1 and 2 are traces. See the review 5 entry |

## Review 1, correctness: two defects, both fixed

### 1a. `atoi` on `--bound-ms` made a typo remove the guard

`--bound-ms` was parsed with `atoi`, whose answer to a non-numeric string is
**0**. And 0 is not an invalid value in this option: it means *no bound at all*.
So `--bound-ms abc` was accepted silently and **disabled the very guard the
option exists to configure.**

⛔ **THIS IS THE SAME DISEASE AS THE `usage()` VARARG BUG** from `f02ae10`,
where an unpassed second argument printed as `0` and a default read as a
number: a zero that looks like a value. Found by asking "what does this option
do with an argument that is not a number", which is a question about the error
path and not about the happy path.

Measured before the fix, and after:

| input | before | after |
| --- | --- | --- |
| `--bound-ms abc` | accepted, treated as **no bound** | `not 'abc'. 0 means no bound at all`, exit 2 |
| `--bound-ms 60000x` | accepted | rejected |
| `--bound-ms -5` | rejected | rejected |
| `--bound-ms 99999999` | accepted (overflows an int comparison) | rejected, range bounded |

Now parsed with `strtol`, with the **end pointer checked** rather than assumed
so `60000x` is rejected for the same reason `abc` is, `ERANGE` honoured, and
the range bounded to an hour because the value is compared against an unsigned
millisecond clock.

### 1b. A close reason from the network reached a terminal unsanitised

`ws_close_reason()` returns a string the **peer** chose, and every consumer
writes it to a terminal: `connect` prints it, and this process is an ssh
`ProxyCommand` whose stderr is read by a person. A reason carrying `ESC`, `BEL`
or a bare `CR` can repaint the line, ring, or overwrite what an operator has
already read, and on r11 the reason is derived from a node's own text.

Found by review 1 asking **what happens to a value that came off the wire on a
path this work widened**. The `c9840e0` change made 1011 print the reason where
it previously printed a fixed sentence, so it widened the exposure.

⛔ AND THE FIX IT FOUND IS THE MORE INTERESTING HALF: `c9840e0` had added a
hand-rolled control-character filter to the `reject` path **and left the close
path unfiltered**, which is the one-read-path-one-write-path violation this
repository exists to prevent. Two filters, one of which the next caller misses.
The rule now lives in **one** place, `note_close()` in `ws.c`, where every close
reason enters the process, and the `reject` comment records why the second one
exists and where it must go if it ever gains a caller.

**Proven to fire, live, not argued.** A node answered `open` with

```
reject {id, reason: "server\x1b[2J\x07boom\rtail"}
```

and both binaries were run against it. Output rendered with `cat -v`:

```
before:  the connection closed before the node answered `ready`
         (code 1011 server^[[2J^Gboom^Mtail)
after:   the connection closed before the node answered `ready`
         (code 1011 server[2Jboomtail)
```

The `^[[2J`, `^G` and `^M` are gone and the printable text survives, which is
the intent: a reason is a sentence an operator reads, not bytes a peer chose.
Control characters are **dropped rather than escaped**, because `^[[2J` in a
message about a connection is noise and the thing needed is `node disconnected`.
Bytes >= 0x80 are kept, so a non-English reason is not mangled.

⛔ The loop cannot overflow. `rl` is clamped to `sizeof close_reason - 1`
before the loop and `k` advances at most once per iteration, so `k <= rl`, and
the terminator lands inside the buffer. Driven directly against a hostile
4 KB input: `k=92`, buffer 124, terminated, zero control characters left.

### A third finding, which was a documentation defect

The comment immediately above the bound check still said *"a relay's own **1008**
is what normally ends this wait"* — the exact claim the same commit had just
measured to be false, three lines away from its own correction. Corrected. ⛔
This is why review 4 has to be a separate review: a commit can fix a claim in
one place and leave it standing in another, and only reading the whole thing
finds the second.

### Review 3, the tests: every guard planted and run, and what that found

> **Reviewed 2026-09-28** over the whole of this session's work. The instrument
> is `tests/plant-matrix.sh`: for every guard added or changed, it plants the
> defect the guard claims to catch and runs the test that claims to catch it.
> ⛔ **THE INSTRUMENT IS THE POINT.** A claim that a guard fires is a claim
> about a counterfactual, and no amount of reading a test establishes a
> counterfactual: reading shows what a test WOULD check, and only running the
> plant shows what it DOES check. This file exists because two sessions wrote
> "every guard was proven to fire" and were wrong, and because three plants came
> back 0/6 on the first pass.

| guard | plant | result |
| --- | --- | --- |
| U1, the bound on the `ready` wait | the bound removed, and set to 0 | **3/3, 3/3** |
| U2, the session move | `ws_move` reverted to a copy | **caught**, 4 named failures |
| U2, the NULL deref | `ws_close` stops nulling `t` | **caught** |
| U3, the 1011 sweep | the sweep's reference removed | **25/25** |
| the 300 KB clamp | the clamp restored | **caught**, with the numbers |
| the node refcount | the refcount removed | **NOT CAUGHT** — see below |
| the stdin EOF invariant | EOF closes the link | **caught**, exit 0 named |
| the ping cap | the cap removed | **caught** |
| the token role check | removed | **caught** |
| the token MAC check | removed | **caught** |
| the token expiry | removed | **caught** |
| the token lifetime | a zero TTL accepted | **caught** |
| the SOCKS policy | removed | **caught**, 6 named failures |
| `ws_close` not setting `closed` | the assignment removed | **NOT CAUGHT** — see below |
| the retry budget | removed | **caught** |
| the CA bundle | the fetch disabled | **caught** |

#### ⛔ Two rows do not go red, and the reason in each case is a fact about the product

**`ws_close` no longer setting `ws->closed`.** The write paths test
`ws->closed` AND `ws->t == NULL`, and every state a session can be in after
`ws_close` has BOTH set, because `ws_close` nulls `t`. So the state that would
expose the missing flag — a closed session whose `t` is live again — is
**unreachable**: a `WsSession` is never re-armed after `ws_close`, because the
only transitions are a fresh init and `ws_move`. The flag is still load bearing,
because a FRAMING error sets `closed` and deliberately leaves `t` alone, but
proving that needs a decoder stub that feeds bytes on demand and this repository
does not have one. `tests/wsmove-test.c` asserts the flag IS load bearing by
building the state directly, and says in the case what that does not prove.

**The node refcount.** Four constructions were tried, the last of them with a
fault point that parks a writer until the node's exit has happened, and a relay
with the refcount removed served every one: 379 writes across the disconnect,
then 38 with the writer held, no crash. ⛔ The reason, measured: `node_done`
ends with `ws_close(ws)`, so the node's session buffers are freed BEFORE the
connection thread reaches `free(nc)`. By the time the NodeCtx goes, the
session an operator holds is already closed, `ws_write` returns -1 on it, and
the writer leaves.

⛔ **SO THE REFCOUNT IS DEFENCE IN DEPTH AND NOT THE LOAD-BEARING GUARD**, and
what makes the write safe is the ORDERING plus the `t == NULL` check. That is a
correction to this file's own earlier claim, which said the refcount "is the
third option and the only one that is correct for both". The refcount is
correct and worth having; it is not what is standing between the two threads.
Case 14 holds them on top of each other anyway, because the protection is an
ORDERING, and an ordering is exactly the thing a later edit moves.

#### ⛔ Two guards were MISSING, and the matrix is what found them

1. **A minted pair name was refused by this relay's own validator, 1 time in 6.**
   `dropssh_random_b64` emits the STANDARD base64 alphabet, which contains `/`,
   and the name becomes a path segment, so the validation immediately below
   rejected it. Measured 5/30, then 0/30 after the fix to hex. ⛔ The deeper
   fault is that a generator and a validator in the same file used two different
   alphabets and neither of them named the alphabet.
2. **The node's exit was a THIRD end of a race the file guarded at two ends.**
   `sweep-release` and `client-last-unref` existed; the node's free did not. It
   is now `node-exit-free`, and the writer is parked with `write-in-flight`,
   which waits on a CONDITION rather than a fixed yield — 2000
   `sched_yield()` calls take microseconds and the node's thread needs
   milliseconds.

#### ⛔ And the instrument has faults of its own, which cost more than the products did

* ⛔ A plant that removes the INSTRUMENT as well as the defect proves nothing
  about either. The first version of the node-refcount plant removed
  `node-exit-free` along with the refcount, so the case measured a race it had
  just made unobservable, and the row printed NOT CAUGHT on a broken build.
* ⛔ A plant row that HANGS is a row that never reports, and a row that never
  reports is a row nobody can tell from a passing one. Two versions hung: one
  passed `--server "sleep 300"`, which `serve` probes at startup and which is
  not a server, and one passed `--server-cmd`, which is not an option at all.
* ⛔ A MATRIX THAT PRINTS NOTHING FOR NINE MINUTES IS A MATRIX NOBODY WATCHES.
  The first two runs produced no output, because output through `setsid` to a
  file is block-buffered. The runner uses `stdbuf -o0` now.
* ⛔ AND ONE ROW REPORTED A CRASH AS "THE CASE COULD NOT RUN", three runs in a
  row with a perfect 3/3. A case that reports a crash as its own setup failure
  has hidden the thing it exists to find, and a 3/3 on that is worth nothing.

### Review 4, the docs: does any of them assert what this work made false?

> **Reviewed 2026-09-28.** The question is not "are the docs accurate" -- it is
> "does any sentence here say something that is now wrong", because a document
> that was correct yesterday and describes yesterday's product is the failure
> this repository keeps finding. Commit `f02ae10` corrected a claim three lines
> from its own correction, and review 1 of that work found it.

**What was swept:** every file that describes a number, a status, a capability
or a mechanism that this session changed. `AGENTS.md`, `docs/open-issues.md`,
`docs/relay-issues.md`, `README.md`, and the help text of every verb, plus every
`⛔` in the source that names a behaviour.

| claim | was | now | why it moved |
| --- | --- | --- | --- |
| e2e case count | "Nineteen" | **"Thirty-five"** | nine cases were added this session; the number was stale at 34 the moment R9 landed |
| probe case count | 9 | **14** | cases 9 to 14 are new, and case 14 is the one that does NOT catch its defect |
| U2, U3 status | 0/6 | **CLOSED**, with the U3 correction | the point of the work |
| the node refcount | "the only one that is correct for both" | **defence in depth; the ORDERING is what holds** | measured: 379 writes across a disconnect with the refcount removed and no crash |
| R9 | "What remains is R9" | **DONE**, with its entry | and the libc split is now a build choice, not a constraint |
| R7, R8, R2, #4, #8 | open or open-issues | **DONE, or BUILT and blocked on a credential** | with the reason each is where it is |
| `dropbear`'s libc | "the shim needs RTLD_NEXT, so a musl dropbear cannot be built" | **still true; the shim is now optional** | `AGENTS.md` said the shim *is* the constraint, and it no longer is |

**Three things found and corrected:**

1. ⛔ **The refcount claim was the wrong kind of true.** "The refcount is the
   only one that is correct for both" is a claim about the refcount, and the
   refcount is fine. What is fine but was implied to be load bearing is NOT:
   the write is safe because `node_done` closes the session before the
   connection thread frees the context, and because `ws_write` refuses a
   session with no transport. A document that says the wrong mechanism is
   load bearing is worse than one that says nothing, because the next reader
   will protect the refcount and move the ordering.

2. ⛔ **"What remains is R9" survived R9 being done**, in the same file, for the
   length of one edit. The status line and the entry were in different places
   and only one of them was being read.

3. ⛔ **And the case count was stale twice**, at 34 and then at 35, because a
   number in prose is a number nobody recomputes. It is now checked against the
   suite's own tally in this review, and the e2e prints its own count so the
   two can be compared.

**What was NOT covered, stated as what would have had to be true to fire:** no
document was checked against a *deployed* relay, so any claim about what the
ajam relay does rests on the measurements in this file and on
`docs/relay-spec/`, which `scripts/fetch-relay-spec.sh` re-checks on a
schedule. ⛔ That is the one class of doc claim here that cannot be settled from
inside this repository, and R8's job is to make it visible rather than to settle
it.

### Review 5, what is NOT covered, as what was swept and what would have had to be true

> **Reviewed 2026-09-28.** An empty result is a result; an empty result with a
> statement of what was swept is worth more than a finding.

**This session, and NOT established:**

* ⛔ **A SOCKS5 forward has never carried a byte.** The listener binds an INET
  socket and `dropssh#6` measured 24/24 that every INET bind is refused with
  EACCES at uid 0, so on this machine the listener cannot be started at all.
  What IS established is the POLICY, on the shipping function, and the two
  configuration guards. What is not: the wire format parsed, the `open`
  honoured by a node, the bytes moved. ⛔ A case that claimed the byte path
  would be a case passing for a reason it cannot see.
* ⛔ **R2's job has never run.** A pair is per-pair and per-role and cannot be
  obtained from the outside; `--mint` answers 403 on a reverse upgrade. The
  script exists, the diagnostics were measured against the live relay with a
  deliberately wrong token, and the job reports "no credential" as its own
  outcome. A green tick on that job is not a pass and the job says so.
* ⛔ **No sanitizer was run, on any of this.** There is no `libasan` and no
  `libtsan` anywhere on this machine, which was established at the start and
  re-confirmed. Reviews 1 and 2 are therefore TRACES and not instruments, and
  the two "unreachable" rows in review 3 are exactly the questions a sanitizer
  would answer. ⛔ The next machine that has one should run this suite under it
  before anything else is changed in `relay.c`.
* ⛔ **The case-3 close-code flake is still unrooted.** 1/100 pre-change, 3/100
  after. It is pre-existing, it is not from this work, and three samples is not
  enough to call the rate unchanged.
* ⛔ **`--retry-budget` was measured at 3 attempts against an absent relay.**
  A budget that interacts with a slow-but-present relay, or with a relay that
  accepts the upgrade and then drops the node, is not measured.
* ⛔ **The cross-relay migration was measured between two of OUR relays with
  the same key.** Against the ajam relay it cannot be, because the ajam relay
  holds a different key, and a pair issued by the ajam relay is not one this
  relay can honour. ⛔ So "a pair issued by our relay works against ours, and
  migrates between ours" is established; "it works against the ajam relay" is
  not, and no version of that claim is in these docs.

**What WAS swept, and what would have had to be true for a finding to fire:**
every writer and reader of `relay_key`, the three SOCKS strings, `Client.refs`
and `NodeCtx.refs`; every place a `wlock` is taken and released, and the lock
order between `tlock` and `wlock` was checked mechanically rather than by
reading, because the early-data path takes both and it is exactly the shape
that inverts. The two new pieces of shared state are written once in
`dropssh_relay_main` before the accept loop and read only afterwards, so there
is no lock on them and there does not need to be one.
### Review 2, concurrency: no defect in this work, and one area re-confirmed

The question is specific: *what is freed while another thread holds a pointer to
it, and what is written under a lock that can block.* The repository's rule is
that the table lock makes it safe to LOOK a pointer up and says nothing about
whether the object is still alive.

**What was swept.** Every writer and every reader of the two structures these
commits touch:

| structure | written by | read by | verdict |
| --- | --- | --- | --- |
| `ws->close_reason`, `ws->close_code` (`ws.c`) | `note_close()`, from the frame decoder | `connect.c` (3 sites), `relay.c:542`, `serve.c:942` | **safe**, and the sanitising loop cannot be observed torn |
| `o->bound_ms`, `wait_started`, `waited_ready` (`connect.c`) | the `connect` main loop | the same loop | **safe**: `connect` is single-threaded by design (B6: no `fork`, no thread, one mbedTLS context) |

**Why `close_reason` is safe, specifically.** The worry with moving the filter
into `note_close` is that it now WRITES a string in a loop, so a second thread
could read a half-written one. Traced rather than assumed: `note_close` is
called from exactly one place, the frame decoder at `ws.c:1120`, which is
reached only from `ws_recv_frame`. That is called from three sites — `relay.c`
line 353 (the operator's own thread, its own session), `relay.c` line 535 (the
node's own thread, its own session) and `serve.c` line 938 (`mux_reader`, the
documented single reader of the node socket). **One reader per websocket, ever**,
so for every session the write and every read of the reason are on the same
thread. The 1011 sweep is the one place a second thread touches a session, and
it writes through `client_release`, not through the decoder.

**The lock question, answered rather than assumed.** The rule about holding a
lock across a blocking write is not engaged by anything in these commits. Both
commits are in `connect.c`, `main.c`, `ws.c` and the test files. `connect` takes
no lock at all; `main.c` touches the option struct before any thread exists; and
`ws.c`'s new code is inside the decoder, which runs on the session's own reader
and already held whatever lock that session had. ⛔ **No new lock is taken, no
new lock is held across a socket write, and no new blocking call was added to
any path**, so the deadlock class this project has already shipped once is not
reached. The pre-existing rule that `ws_close_with` can sit for 30 s on a full
socket is unchanged and still correctly kept outside `tlock`.

**What was NOT covered by this review, stated as what would have had to be true
to fire.** It examined the two structures the commits changed. It did not
re-audit the whole of `relay.c`'s table, and it did not run a thread sanitiser
(`-fsanitize=thread`) over a concurrent session, which would be the instrument
that settles the U2/U3 questions rather than reasoning about them. ⛔ That is
the next review's work, and it needs a real tool rather than a reading.

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
an unanswered session with **1013 `node open timeout` after 15 s** (measured
2026-09-28 at r11; this entry previously said 1008 at ten seconds, which was
wrong in both numbers). Both end the session long before
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

# U2, closed: one owner per session, and a test that says which

**Done 2026-09-28.** U2 was 0/6 because every refusal path in the operator's
function sits **above** the move, so no probe could tell a move from a copy.

**What changed in the product.** The move is now `ws_move(dst, src)`, one
function in `src/ws.c` that takes a **pointer to the source** and clears it
itself. The two hand-written versions were `dst = src; memset(&src, 0, ...)`
and `*dst = *src; memset(&src, 0, ...)`. Both are correct and **both are one
edit away from a copy**: delete the `memset` and the ownership is aliased again,
with no compiler error and no test. Clearing the source from inside the move is
what removes the second statement, and the source is left with no transport and
no buffers, so every existing `ws_close(&ws)` on a refusal path above the move
is a no-op **by construction** rather than by a convention someone must
remember. `src/relay.c` now calls it at both move sites.

**And a NULL dereference went with it.** `ws_close` used to NULL `ws->t` and
leave `ws->closed` clear; the write paths tested only `ws->closed`, and
`send_frame` dereferences `t` unconditionally. So a write on a closed or
moved-from session was a NULL dereference, and the operator's `!open_ok`
refusal — the one write below the move — is exactly such a write. `ws_close`
now sets `closed` as well, and `ws_write`, `ws_write_text` and
`ws_shutdown_tx` test `t == NULL` too, so "the session is finished" is one
fact with two representations that cannot disagree.

**⛔ WHY THE GUARD IS A NEW BINARY AND NOT A THIRD PROBE CASE.** A case that
drives a refusal below the move can only observe *a crash*, and only when the
refusal and a second close interleave. U2 is not a race: it is an **ownership**
property, and ownership is answerable directly. `tests/wsmove-test.c` links
the real `src/ws.c`, `src/buffer.c` and `src/util.c` — the shipping code, not a
copy of it — and asks the one question a copy cannot pass: after the move, does
the **source** own anything?

| build | what it is | result |
| --- | --- | --- |
| correct | `ws_move` clears the source | **6 passed, 0 failed**, exit 0 |
| PLANT: the clear removed | a copy, which is the U2 defect | **1 passed, 4 failed**, exit 1, every failure named |

⛔ **AND THE FIRST VERSION OF THE TEST WOULD HAVE PASSED AGAINST THE DEFECT,
which is the whole reason it is written the way it is.** It asserted only that
the source was empty, and a copy followed by a `memset` is also empty. The
assertion now asks the ownership question *before anything is freed*, because on
a copy the first close frees a buffer the other name still points at and the
test process dies before printing which rule broke. A test whose failure output
is discarded by the crash it exists to catch has caught nothing. `setvbuf` is
unbuffered for the same reason.

**`tests/mux-probe.py` case 9** still drives a refusal below the move, because
the integration path is worth having even when the unit test is the one that
names the defect. Its two plants are the move reverted to a copy and the node's
context freed with no reference.

# U3, closed: the 1011 sweep, and a correction to this document

**Done 2026-09-28. ⛔ THE 0/6 IN THE TABLE ABOVE WAS MEASURED AGAINST THE WRONG
SCENARIO, and this entry is the correction.**

The table said the window was "narrower than 6 probe runs; case 4 forces the
ordering but does not land inside it". That is true, and it is true of **the
scenario it was measured on**: case 4 disconnects the **node** while the
**operator stays attached and idle**, so the operator's thread is parked in
`ws_recv_frame` and does not reach its last unref while the sweep is running.

**Closing both sockets in the same instant — which is what a real teardown looks
like — makes the window wide, not narrow.** An operator whose socket closes is
in `client_cleanup`, dropping the table's last reference, while the node's
sweep is holding a pointer to the same `Client`.

| build | what it is | node and operator both closed together | relay died |
| --- | --- | --- | --- |
| original, unplanted | the refcount is there | 25 runs | **0/25** |
| original + U3 plant | `c->refs++` removed from the sweep | 25 runs | **25/25** |
| fixed + fault injected | the refcount is there, `DROPSSH_RELAY_FAULT` set | 25 runs | **0/25** |

`tests/mux-probe.py` case 10 drives that scenario and is **3/3 against the
original code with the plant applied**. So the guard needed a different
**scenario**, not a fault-injection hook.

**⛔ THE FAULT-INJECTION HOOK EXISTS ANYWAY, AND IT IS NOT WHAT CLOSED U3.**
`DROPSSH_RELAY_FAULT` names one of two points, `sweep-release` and
`client-last-unref`, and the relay yields there. It is read once at startup, an
unrecognised value is a **hard error** rather than a silently ignored one, and
it is inert unless set. It was the plan, and the measurement showed the plan was
wrong: the race was reachable without it. It is kept because a yield at both
ends of a window this file has crashed on twice is a cheap way to keep the
window open on demand, and **kept and labelled as not having closed U3** is the
only honest description of it.

**A real use-after-free went with it, and it is not U3.** `NameSlot.node` was a
`WsSession *` — a pointer **into** a heap `NodeCtx` — and the node's own
connection thread called `free(nc)` on its way out while an operator held that
pointer and was about to write through it, on both the data path and the
`!open_ok` path. `wlock` does not close it: `wlock` serialises operators
against each other, and the node's exit path never took it. The comment that
stood there claimed "the context outlives every use of it", which was true of
the node's own uses and false of every operator's. The table now holds a
`NodeCtx *` and readers hold a reference, the same mechanism `Client` already
used, because two rules have to agree and this file has had three double frees
from one rule being applied in one place and forgotten in another.
