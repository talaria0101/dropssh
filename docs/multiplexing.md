# Sessions are one-per-socket today, and the relay protocol is not

## What is shipped

`dropssh relay` and `dropssh serve` pair one operator with one node and splice
their bytes. That is a **rendezvous**, and it works: `tests/e2e.sh` carries a
pubkey session to uid 0 through it, and a 270 KB transfer comes back byte for
byte.

## What the relay's own protocol is

The ajam relay's reverse path is **multiplexed**, and this is its own words:

> The node receives JSON control messages `hello`, `open {id}`, and
> `close {id}`. It replies `ready {id}` after its own local connection is
> ready, or `reject {id,reason}`. Each node binary frame starts with the 32
> ASCII hex characters of the session id, followed by up to 64 KiB of bytes.
> The operator waits for `ready`, then sends and receives raw binary frames.

So a node holds ONE websocket open and serves MANY sessions on it, told apart
by a 32-hex id at the front of every frame. One session per socket is not a
smaller version of that; it is a different protocol, and it cannot talk to that
relay at all. It also means two operators cannot both get in.

## Measured, on 2026-09-27, attempting the change

The multiplexed implementation was written and it does not work. What was
measured while building it, and recorded because each of these is a trap the
next attempt walks into:

| defect | what it looked like |
| --- | --- |
| a control message is a TEXT frame, session bytes are BINARY | the node rejected the relay's own `hello` as a malformed frame, one message after a successful handshake |
| the 32-hex id is a frame PREFIX, not a field | sending a control message as binary makes the far end read it as a truncated id |
| `ws_read` returns "whatever arrived", not one frame | two frames arriving together became one, and a control message was parsed with session data still attached to it |
| `decode_available` appended every decoded frame to one buffer | a text control frame followed by a binary data frame reported the binary opcode for both, and a control message was demultiplexed as session bytes |
| a reader that returns a pointer without consuming it | the same frame was returned forever, and the session was flooded until the client timed out |
| a peer that frames a leg that the relay frames for it | the relay's two legs are NOT symmetric: it **prepends** the session id on the operator's leg and **strips** it on the node's. A node that omits the prefix has its frames silently dropped; an operator that adds one has it doubled. Both fail with no error, and both look like a relay fault. `docs/reverse-relay.md` has the four-way measurement. |
| one reader per socket, and it is not a session | N sessions each reading one websocket is a race on its framer buffer, and it mostly works with one session, which is what makes it dangerous |
| `fork()` copies a TLS context, not just descriptors | a child writing while the parent reads corrupts the record layer, and the child reported `could not write to the relay` on a connection that was fine |
| a session is a race between "the fork has set its socket" and "the operator's bytes arrived" | the first bytes of the ssh stream were dropped, and the symptom was the same `Exit before auth` |

Every one of those produced a session that authenticated, started dropbear, and
went silent with every log line looking correct. Two of them produced the
identical error message from a completely different cause, which is the reason
the table exists: `Exit before auth` in this codebase means a framing bug until
proven otherwise, and it has meant three different things.

## The shape that does not have these bugs

One event loop per socket, no threads and no forks on a connection:

* **one reader per websocket, ever.** The node's socket is read by the node's
  loop and nothing else. Frames are dispatched to sessions by id, so a frame has
  exactly one possible destination.
* **one writer, serialised.** A websocket frame is a header and a payload
  written together; two threads interleaving them produce a frame whose length
  and payload disagree, and the far end desynchronises on the NEXT frame, which
  is another session's bytes read as an id.
* **one event loop per connection in the relay**, with `poll()` on the accepted
  descriptor, so a socket's lifetime is owned by the thread that accepted it
  and no cross-thread lifetime exists at all. The attempt above used one thread
  per connection and still had a socket closed by another thread.
* **the frame boundary is the message boundary**, in the framer, with the
  opcode travelling with the frame it belongs to. This is the fix for the two
  rows above that are about coalescing, and it is the one that is easy to get
  wrong and hard to see.
* **bytes that arrive before a session's server exists are queued, not
  dropped**, and the queue is drained on every turn of the loop rather than
  once, because "once" wins one race and loses the other.

## What is not done

The multiplexed path is not in this release. `dropssh serve` and
`dropssh connect` work against `dropssh relay` and against a **forward** relay
such as `tcp.ssh.relay.ajam.dev` (`--mint`, `--path /connect/<host>/<port>`),
both measured with a real session and exit 0. They do not yet speak the
multiplexed reverse protocol, so `serve` against that relay needs a
name-scoped operator token and a node that speaks its framing.

That is the next piece of work, and this page is the design note for it.
