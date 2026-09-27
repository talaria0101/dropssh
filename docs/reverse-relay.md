# The reverse relay protocol, as measured

**Read this before implementing the reverse path.** Everything here was
observed live against `tcp.ssh.relay.ajam.dev` on 2026-09-27, and two findings
contradict the relay's own published documentation.

## Getting a pair is now self-service

```sh
curl -sS -X POST "https://tcp.ssh.relay.ajam.dev/v1/pair" \
     -H "content-type: application/json" -d '{}'
```

```json
{
  "name":          "p-d0ea8678298c4d62bd1d77a9b3d55cc7",
  "node_token":    "2de914d4cff1bbd90f...",
  "connect_token": "0cdd4c283fc4d465c7...",
  "stop_token":    "45e9ea5ee111dfb2d5...",
  "expires":       1790763251721
}
```

`expires` is ms since epoch, never later than 72h after creation. The agent
keeps `node_token` and hands `connect_token` to its operator over a channel
they already trust. This is the self-service exception to "reverse access is
never self-service" that the earlier revision of the relay's docs described.

This changes what is possible: **there is no longer a blocker requiring an
operator-issued credential.** A node can be registered and reached end to end by
an agent alone.

## Entry points

| role | address | token |
| --- | --- | --- |
| node | `wss://tcp.ssh.relay.ajam.dev/v1/node/{name}` | `node_token` |
| operator | `wss://tcp.ssh.relay.ajam.dev/v1/connect/{name}` | `connect_token` |
| status | `https://tcp.ssh.relay.ajam.dev/v1/status/{name}` | **`connect_token` only** |
| stop | `POST https://tcp.ssh.relay.ajam.dev/v1/stop/{name}` | `stop_token` |

⛔ **`/v1/status` ACCEPTS THE `connect_token` AND NOT THE OTHERS.** Measured, all
four combinations against a live pair:

```
node_token     -> 403 "reverse: forbidden"
connect_token  -> 200 {"online":false,"sessions":0}
stop_token     -> 403 "reverse: forbidden"
```

The documentation index calls it "authenticated presence and session count"
without saying which credential, and a status poll that 403s reads as "the node
is unreachable" rather than "you presented the wrong token". Use the
`connect_token`.

The token goes in `X-Relay-Token`, or `?token=`. A successful upgrade carries
`X-Relay-Version: reverse-v1`.

## The protocol

Both peers dial out. The node's socket is long-lived and carries every session
at once.

A reference operator is 30 lines of JavaScript and lives at
`docs/08-reverse.md` in the relay's repository; it is the authority on the wire
format and the measurements above agree with it.

**Control messages are TEXT frames (opcode 0x1) with no id.** They are JSON:

| direction | verb | when |
| --- | --- | --- |
| relay -> node | `{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}` | immediately after the node's upgrade |
| relay -> node | `{"type":"open","id":"<32 hex>"}` | an operator has arrived |
| node -> relay | `{"type":"ready","id":"<32 hex>"}` | the local ssh server is up |
| node -> relay | `{"type":"reject","id":"<32 hex>","reason":"..."}` | it could not be started |
| relay -> node | `{"type":"close","id":"<32 hex>"}` | the session is over |
| either | `{"type":"bye"}` | that side is finished |

The field is `type`, not `verb`. An earlier reading of the docs said `verb`,
and code that parses `verb` sees no control message at all.

**Data frames are BINARY (opcode 0x2), and the two directions are NOT
symmetric.** This was measured four ways in one session, and the asymmetry is the
single most important thing to know before writing a client:

```
operator sends b"OPBARE"          (6 bytes, no id)
  -> node receives 38 bytes:  <real id> + b"OPBARE"      <- relay PREPENDS
operator sends <id> + b"OPID"    (38 bytes)
  -> node receives 68 bytes:  <real id> + <id> + b"OPID"  <- relay PREPENDS AGAIN

node      sends b"NDBARE"         (6 bytes, no id)
  -> operator receives NOTHING                             <- relay DROPS it
node      sends <id> + b"NDID"   (38 bytes)
  -> operator receives 4 bytes: b"NDID"                    <- relay STRIPS the id
```

So, stated as rules:

| direction | the peer sends | the relay does | the far side receives |
| --- | --- | --- | --- |
| operator -> node | **bare payload, no id** | prepends the session id | `id + payload` |
| node -> operator | **`id + payload`** | strips the id | **bare payload** |

⛔ **NEITHER PEER ADDS AN ID ON THE OPERATOR LEG.** The operator sends raw ssh
bytes and the relay frames them. This is exactly what the reference operator in
`docs/08-reverse.md` does: `ws.send(b)` on stdin with no framing at all.

⛔ **THE NODE MUST PREFIX THE ID.** A bare payload from the node is **silently
dropped**: the operator receives nothing, no error, no close, and the session
just goes quiet. Measured above. This is the failure mode that will cost an
afternoon, because a node that omits the prefix looks like a relay problem and
is not one.

⛔ **A BOGUS ID FROM THE OPERATOR IS REWRITTEN, NOT REJECTED.** Sending
`"f"*32 + b"XXXX"` from the operator arrives at the node as
`<real id> + b"XXXX"`: the id is replaced with the real one and the payload is
kept. Measured. It is not exploitable across pairs, because a token is scoped
to its own pair and the far end must already be on the node's socket, but it
means **the id in an operator frame is not an addressing field and must not be
trusted or relied on**; it is ignored.

A short frame with no id at all is handled the same way: `b"12345678"` from the
operator arrives as `<real id> + b"12345678"`, so the relay prepends and does
not require the operator to include anything.

**The operator must not send `ready` as a text frame.** Measured: it is refused
with a Close frame carrying `binary frames required`. Only the node answers
`open` with `ready`. Note the asymmetry, because it is the relay's and not a
convention: the node's `ready` is forwarded to the operator as a **text** frame
and the operator parses it, so a client that only reads binary frames on that
socket will sit waiting for data that has already arrived as text.

**The node must answer `open` promptly.** Measured: an operator whose `open`
goes unanswered is closed with a Close frame carrying `node open timeout`, and
the node then receives `close` for a session that never ran.

## What a node must do, in order

1. `POST /v1/pair`, keep `node_token` and `connect_token`, remember `expires`.
2. `GET wss://.../v1/node/{name}` with `X-Relay-Token: <node_token>`.
3. Read the relay's `hello`. Record `maxFrameBytes` and `maxSessions`; they are
   the relay's limits, and the node's own limits should not exceed them.
4. For each `{"type":"open","id":I}`: start a local ssh server on a socketpair,
   and **immediately** answer `{"type":"ready","id":I}` as a text frame, or
   `{"type":"reject","id":I,"reason":"..."}`.
5. For each **binary** frame you receive: the payload is **bare**, with no id to
   parse. Write it to the session's socket. For each binary frame you **send**:
   prefix the 32-character id, or the relay drops it and the operator receives
   nothing at all.
6. For each `{"type":"close","id":I}`: tear down that session only. Other
   sessions are on the same socket and must survive.
7. On disconnect, redial with exponential backoff and jitter, capped. The
   existing `dropssh serve` already does this.

## What an operator must do, in order

1. `GET wss://.../v1/connect/{name}` with `X-Relay-Token: <connect_token>`.
2. Read **both** frame types. A **text** frame is a control message: the node's
   `ready` is forwarded to the operator by the relay as text, and ignoring text
   frames means waiting forever for a `ready` that already arrived. A **binary**
   frame is session data with **no** id prefix, and the whole payload goes to
   stdout.
3. Write stdin as a **bare** binary frame. Do not prefix an id; the relay adds
   it. See the table above for why this is the opposite of what the node does.
4. Exit when the socket closes or a `close` arrives.

## Status and stop

```sh
curl -sS "https://tcp.ssh.relay.ajam.dev/v1/status/$NAME" -H "X-Relay-Token: $TOKEN"
curl -sS -X POST "https://tcp.ssh.relay.ajam.dev/v1/stop/$NAME" -H "X-Relay-Token: $STOP_TOKEN"
```

## Errors observed

| message | meaning |
| --- | --- |
| `403` on the node or connect upgrade | absent or wrong token for that role |
| `503` on the connect upgrade | the node was not connected when the operator arrived |
| Close `node open timeout` | the node did not answer `open` in time |
| Close `binary frames required` | a text frame was sent where a data frame was required |

## Audit of the relay's published reference operator

`docs/08-reverse.md` in the relay's repository is a 30-line reference operator,
pasted into a session on 2026-09-27. **It is the authority on the protocol, and
the four-way measurement above agrees with it**: the operator's leg is
unframed, which is the single most surprising thing about the protocol and the
thing this file gets right.

The pasted text has **two defects that stop it running** and one that discards
a diagnosis. Both fatal ones are recorded because this is a reference people
will copy, and because "the relay's own example does not run" is a claim that
needs a measurement rather than an opinion.

Audit of the pasted reference operator, line by line, against the four-way
measurement in docs/reverse-relay.md.

1. `new WebSocket(`${wsBase}/v1/connect/${name}?token=${token}`)`
   Token in the QUERY, not the X-Relay-Token header. Measured: the header works
   and is better (a URL is written to every access log on the way). Both are
   accepted here, so this is a preference, not a bug. Worth noting in a doc that
   says the header is preferred.
   OK, with a caveat.

2. `binaryType = "arraybuffer"`
   Correct and REQUIRED. Without it, binary frames arrive as Blob and
   Buffer.from(e.data) on a Blob gives the wrong bytes. OK.

3. `if (typeof e.data !== "string")`
   This is BACKWARDS. A string is a TEXT frame, which is a control message.
   As written, every control message falls into the try/JSON.parse branch
   (which is what you want) AND every binary frame also enters the `if`
   because a binary frame's typeof is "object", not "string" -- so a BINARY
   frame is run through JSON.parse first. JSON.parse of ssh bytes throws, the
   catch calls fail(), and the session dies on the first data frame.
   The condition should be `if (typeof e.data === "string")` or, read as
   "not a control message", the branch bodies are swapped.
   LIKELY A TRANSCRIPTION SLIP, and a fatal one: it breaks the happy path.

4. `for (const b of queue.splice(0)) ws.send(b); return;`
   Drains the stdin queue once ready. Correct in shape. One gap: `ws.send(b)`
   on stdin BEFORE ready queues in the process, and `queue.splice(0)` empties
   it in one go, so ordering is preserved. OK.

5. `if (!ready) queue.push(b); else ws.send(b);`
   Correct, and the queue is what makes the operator's send path legal: the
   relay prepends the id on this leg, so the operator sends BARE bytes. The
   bridge does exactly that. OK, and this is the part that matters most.

6. `if (!ready) fail("data before ready")`
   Guards the case where the node sends data before `ready` reaches the
   operator. Reasonable. OK.

7. `ws.addEventListener("close", () => process.exit(0))`
   Exits 0 on ANY close, including an error close. The relay's legacy PoC
   distinguishes 1000 from an error close and reports it, because a close
   carrying `node open timeout` or `binary frames required` is the diagnosis.
   This bridge throws that away. Minor, and it is the reference, not a
   requirement.

8. `process.stdin.on("end", ...)` line
   SYNTAX ERROR as pasted: `SyntaxError: missing ) after argument list`.
   `setTimeout(() => process.exit(0, 3000);` is missing a `)` before the `;`.
   The prose says to delete the whole setTimeout line for sessions over a
   minute, and the two instructions only balance if the line is REPAIRED first:
     process.stdin.on("end", () => { closing = true; try { ws.close(); } catch {} process.exit(0); });
   Verified: node --check rejects the pasted line and accepts the repaired one.

9. `closing = true` then `fail()` exiting 0
   Means a teardown-triggered error is not reported. Intentional and fine.

CONCLUSION
Two things need fixing before that file runs:
  * line 3's condition, which inverts text and binary and breaks every session
  * the stdin "end" line's missing paren
and one worth changing if you keep it: read the close code and reason, so a
`node open timeout` is visible instead of a silent exit 0.

## Authentication, and what was tested

Tokens are scoped to their own pair **and to their own role**, verified on
2026-09-27 with a fresh pair per case:

| attempt | result |
| --- | --- |
| `node_token` on its own `/v1/node/{name}` | 101 |
| `node_token` on **another pair's** `/v1/node/{name}` | 403 |
| another pair's `node_token` on this pair's name | 403 |
| a garbage token | 403 |
| `node_token` on `/v1/connect/{name}` | 403 |
| `connect_token` on `/v1/node/{name}` | 403 |
| a second node on a name already connected | 409 Conflict |

So the role separation and the per-pair scoping both hold, and a first
measurement that appeared to show otherwise was a fault in the test: it judged
"accepted" by the absence of an exception, and a 403 arrives as a status line
rather than an exception. **Assert on the status line, not on whether the call
threw.**

## Forward transport, unchanged

Unaffected by any of the above and already working in this repo:

```sh
curl -sS -X POST "https://tcp.ssh.relay.ajam.dev/v1/mint" -H "content-type: application/json" -d '{}'
ssh -o ProxyCommand='./dropssh connect --mint --path /connect/railway' root@railway.new
```

`/connect/{host}/{port}` is raw bytes, no id, no control messages, no
multiplexing. `dropssh connect` decides which of the two it is talking to by
counting the path segments after `/connect/`: one segment is a node, two is a
target.

## Sources

* <https://tcp.ssh.relay.ajam.dev/llms.txt> (version `2026-09-27-r2`)
* <https://tcp.ssh.relay.ajam.dev/index.md>
* The original podssh work, which this reimplements in C:
  <https://github.com/Azathothas/podbox/pull/67>
