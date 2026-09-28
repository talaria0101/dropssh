# tcp.ssh.relay.ajam.dev — WebSocket ⇄ TCP relay

A stateless Cloudflare Worker that exposes raw TCP as a WebSocket, so an environment whose only
egress is HTTPS/443 can reach an SSH server — or any TCP service — on the public internet.
Bytes inside the WebSocket are the raw TCP stream: SSH stays end-to-end encrypted between your
client and the target, and this relay only forwards ciphertext.

This deployment: **default**.
Outbound TCP prefers the **Workers VPC network binding** (egress by Cloudflare Gateway, a less
shared address pool) and falls back to a direct Worker socket.

## Exact addresses

| What | Address |
| --- | --- |
| This document | https://tcp.ssh.relay.ajam.dev/ |
| Agent documentation index | https://tcp.ssh.relay.ajam.dev/llms.txt |
| Full raw Markdown for agents | https://tcp.ssh.relay.ajam.dev/llms-full.txt |
| Machine-readable pool + ranking | https://tcp.ssh.relay.ajam.dev/relays.json |
| Diagnostics | https://tcp.ssh.relay.ajam.dev/trace |
| Liveness / this relay's colo + egress road stats | https://tcp.ssh.relay.ajam.dev/health |
| Typed client bundle (curl-able) | https://tcp.ssh.relay.ajam.dev/client/relay.mjs |
| Abuse contact | https://tcp.ssh.relay.ajam.dev/.well-known/security.txt |
| Default named relay (WebSocket) | wss://tcp.ssh.relay.ajam.dev/ → `railway.new:22` |
| Arbitrary target (WebSocket) | wss://tcp.ssh.relay.ajam.dev/connect/<host>/<port> — e.g. wss://tcp.ssh.relay.ajam.dev/connect/example.org/22 |
| Reverse node (control host only) | wss://tcp.ssh.relay.ajam.dev/v1/node/<name> |
| Reverse operator (control host only) | wss://tcp.ssh.relay.ajam.dev/v1/connect/<name> |

Named relays:

- `wss://tcp.ssh.relay.ajam.dev/connect/railway` → `railway.new:22` (banner `SSH-2.0-Go`) — target bucket `us` — Railway free-VM SSH gateway (anonymous quota-gated)

## The colo pool — pick the relay nearest to you and the target

- `tcp.ssh.relay.ajam.dev` — client-nearest colo (no placement)
- `tcp-1.ssh.relay.ajam.dev` — bucket `ap`, placement `aws:ap-south-1` — South/East Asia and Oceania
- `tcp-2.ssh.relay.ajam.dev` — bucket `eu`, placement `aws:eu-central-1` — Europe, Middle East, Africa
- `tcp-3.ssh.relay.ajam.dev` — bucket `us`, placement `aws:us-east-1` — North and South America

`GET /relays.json` ranks the pool for **your** edge colo and the target, and accepts
`?prefer=client|target|auto`, `?region=<bucket>`, `?relay=<name>`, `?spread[=n]`
(rotate the front of the list to vary the egress colo), or `?host=&port=` for an explicit target.

Probe before committing if you care about latency (`time_starttransfer` shows the hop to the
relay's placement colo; every host shares the same anycast edge):

```sh
for h in tcp.ssh.relay.ajam.dev tcp-1.ssh.relay.ajam.dev tcp-2.ssh.relay.ajam.dev tcp-3.ssh.relay.ajam.dev; do
  curl -s -o /dev/null -w "%{time_starttransfer} $h\n" "https://$h/health"
done | sort -n | head -1
```

## Forward transport (generic TCP)

Open a WebSocket to `wss://tcp.ssh.relay.ajam.dev/connect/<public-host>/<port>` with the forward token in
`X-Relay-Token` (or the token query/path form). Binary frames are copied to the target TCP
socket in order; target bytes return as binary frames. A target may speak any TCP protocol.

## Getting a token

- Forward tokens are self-minted: `POST /v1/mint` with an empty body
  (`"{}"` accepted) returns `{token, expires, scope}` (`expires` is ms
  since epoch). Exact command (curl only, non-interactive — paste as-is):
  `curl -sS -X POST "https://tcp.ssh.relay.ajam.dev/v1/mint" -H "content-type: application/json" -d '{}'`.
  Tokens look like `ephm1.<exp>.forward.<mac>` and expire at
  most 72h after minting; the token is checked when each session is established
  (each WebSocket upgrade), not per frame, so an expired token is rejected up front.
- Other statuses: 405 wrong method, 400 bad body, 413 oversized body,
  429 brake with Retry-After.
- Reverse credentials are operator-issued (the operator admits the node name
  first) except for agent-created pairs (see Reverse transport below), which mint their own.
- No valid token is ever published here: a token quoted on a web page, a log
  line, or an example is either expired text or somebody else's credential.
- Send a forward token in `X-Relay-Token`; use `?token=` or `/t/<t>/...`
  only when headers are unavailable, since URLs can appear in logs. Send a
  reverse token only as `X-Relay-Token` or `?token=`.
- A `403 missing or wrong token` means absent or wrong, not that the target
  is unreachable. A `403` that names the target (`not in the ALLOW list`) is a
  policy denial — minting a fresh token will not fix it. A `503 forward relay
  authentication is not configured` is a server misconfiguration: ask whoever
  gave you this relay address for an operator token. Keep tokens out of shell
  history, screenshots, and issue reports.
- If minting answers 503, issuance is disabled or unconfigured: ask whoever
  gave you this relay address for an operator token.

## Client integration

Any WebSocket client can use the forward byte transport. It should pass the token in a header when
possible, send binary frames, skip zero-length keepalives on receive, and verify the end service's
own authentication and identity (for SSH, its host key). The typed client
bundle is served at `/client/relay.mjs` (Node 22+, no dependencies; verify
against `/client/index.json`); its source is `client/src/` in the repository
and the integration suite drives it, so a protocol change is a red suite. The
current server acceptance steps are in `TRY.md` in the source repository.

## Diagnostics — /trace

- `https://tcp.ssh.relay.ajam.dev/trace` — your edge colo/city/country/ASN, this relay's identity, egress-road counters.
- `https://tcp.ssh.relay.ajam.dev/trace?target=github.com:22&banner=1` — dials the target: address used, family, connect
  time, first banner line.
- `https://tcp.ssh.relay.ajam.dev/trace?egress=1` — dials an echo-IP service through the relay and prints the address the
  target sees (the relay's egress, not yours). `&path=vpc|direct` picks the road, `&format=text`
  prints `key=value` lines.

## Reverse transport (outbound-only nodes)

The control host exposes `/v1/node/<name>` for a node's persistent outbound WebSocket,
`/v1/connect/<name>` for an operator's raw-byte session, authenticated
`/v1/status/<name>` for presence, and `POST /v1/stop/<name>` to stop an admitted node and
its sessions. Credentials are HMAC-SHA256 tokens scoped to each name and
role; send them in `X-Relay-Token` or `?token=`. Agent-created pairs need no
admission (control host only): the agent calls `POST https://tcp.ssh.relay.ajam.dev/v1/pair`
with an empty body or `'{}'`
(`curl -sS -X POST "https://tcp.ssh.relay.ajam.dev/v1/pair" -H "content-type: application/json" -d '{}'`),
which returns `{name, node_token, connect_token, stop_token, expires}`
(`expires` ms since epoch, within 72h). It connects `WSS` `/v1/node/<name>`
with `node_token`, and gives the operator `connect_token` for
`/v1/connect/<name>`. Other statuses: 405 wrong method, 400 bad body,
413 oversized body, 429 brake with Retry-After. Accept a connect token only
from your own agent over your trusted channel (TOFU). The node receives JSON control messages
`hello`, `open {id}`, and `close {id}`. It replies `ready {id}` after its own local
connection is ready, or `reject {id,reason}`. Each node binary frame starts with the 32 ASCII
hex characters of the session id, followed by up to 64 KiB of bytes. The operator waits for
`ready`, then sends and receives raw binary frames. Direction is strict both ways: the
operator receives text control frames and sends binary data frames only — an operator text
frame closes the socket `1003`. A refused session arrives as a `reject` text frame carrying
the node's full reason, followed by the socket close. The operator leg carries **no framing
at all**: the relay never reads an id out of an operator frame, treats the whole frame as
payload, and prepends the session's real id. An id an operator sends is rewritten, not
honoured, so a client must never treat a 32-byte prefix as addressing. A node frame naming
an unknown session is a node-side fault: the relay logs it and closes the node `1003`.
One name holds one node socket: a second node connection is refused HTTP 409 before
accept, so the live node and its sessions are undisturbed. Hitting `/v1/node/<name>`
or `/v1/connect/<name>` without a WebSocket upgrade answers 426.
Nothing in this protocol assumes SSH, a specific client implementation, or a fixed local
port. See `docs/08-reverse.md` in the source.

## Reverse close codes (version 2026-09-28-r12)

Every close above, in one table. "Observed by" is the leg whose socket is
closed — with one exception: when the relay itself closed the node socket for
cause, the operator observes that cause too (the close is forwarded to its
sessions instead of the `1011` default), so a `side: node` row can reach the
operator leg. Generated from `worker/src/reverse.js` at this version and checked by
`node scripts/todo/check.mjs --close-table`.

| Code | Reason | Observed by | Meaning and action |
| --- | --- | --- | --- |
| 1001 | operator stopped reverse relay | either | `POST /v1/stop/<name>` ran. Expected during revocation; do not retry the same name. |
| 1001 | pair expired | either | The 72h pair TTL elapsed. Create a new pair with `POST /v1/pair`. |
| 1003 | unknown session id | node | Node frame named a stale or invented id. Re-open the session; never invent addressing. |
| 1003 | invalid control JSON | node | Node control was not JSON. Send `{"type":...,"id":...}` text frames only. |
| 1003 | invalid session id | node | Control `id` is not 32 lowercase hex. Fix the id codec. |
| 1003 | unknown control type | node | Control `type` is not `ready`, `reject` or `close`. Check the type strings. |
| 1003 | bad multiplex id | node | The 32-byte binary prefix is not hex. Fix the id prefix. |
| 1003 | data before ready | node | Node data arrived for a session the node never readied. Answer `open` with `ready` first. |
| 1003 | binary frames required | operator | Operator sent a text frame. The operator leg is binary-only (it receives a text `ready`, it never sends one). |
| 1008 | unknown role | either | Socket carried no role attachment. Unreachable through the normal connect paths; reconnect if seen. |
| 1008 | wait for ready | operator | Operator data arrived before the node readied the session. Wait for the text `ready` frame. |
| 1009 | control frame byte cap | node | Node JSON control exceeded 4 KiB. Keep controls small. |
| 1009 | bad multiplex frame | node | Node binary frame under 32 bytes or over 65568 (32-byte id plus 65536 payload). Always prefix the full id. |
| 1009 | session byte cap | operator | One session exceeded 64 MiB in both directions. Open a new session. |
| 1009 | frame byte cap | operator | One operator frame exceeded 65536 payload bytes. Chunk to 64 KiB. |
| 1011 | relay backpressure | either | Over 1 MiB queued for a slow receiver. Slow down; the undelivered frame is dropped. |
| 1011 | node unavailable | operator | The `open` could not be queued to the node. Retry opening the session. |
| 1011 | node offline | operator | Operator data arrived with no node connected. Wait for the node and retry. |
| 1011 | node disconnected | operator | The node socket ended without a reason the relay could forward (clean leave, network drop). When the relay itself closed the node for cause, the operator gets that cause instead. Reconnect the session. |
| 1011 | socket error | either | Transport-level socket error. Reconnect. |
| 1013 | node open timeout | operator | No `ready` within 15 s of `open`. The node must answer promptly or the session is reaped. |
| 1013 | reverse message rate cap | either | The optional per-name message fuse tripped. Back off. Production leaves it off (`REVERSE_MAX_MESSAGES_PER_MINUTE=0`). |
| 1000 or 1011 | node-supplied | operator | Per-session refusal, not a fixed pair: node `close` relays as `1000`, node `reject` as `1011`, both carrying the node's own reason — or the literal type string when the node sent none — truncated to 100 chars (`worker/src/reverse.js:354`). Parse the reason, not the code. |
| 1000 | session ended | either | Answer to a client-initiated socket Close. The relay never leaves a closing socket hanging: the initiator gets a clean handshake instead of timing out to `1006`. |

## Request knobs (connect)

| Knob | Meaning |
| --- | --- |
| `?family=4` / `?family=6` | resolve the target over DoH and dial only that address family (default `auto`) |
| `?path=vpc` / `?path=direct` | force the egress road for this session |
| `?dial=lazy` | dial on the first client byte instead of before the upgrade |
| `?precheck=<ms>` | wait up to ms for the target's first bytes before completing the upgrade (clamped to the server cap; `0` skips — use for servers that wait for the client to speak first) |
| `?token=<t>` / `/t/<t>/connect/...` / `X-Relay-Token` | token, when the operator set one |

## Protocol (for other clients)

1. `GET <address>` with `Upgrade: websocket`; no subprotocol; extension negotiation is the
   runtime's (a client that offers `permessage-deflate` gets it, one that offers nothing is
   uncompressed — the passthrough is byte-transparent either way).
2. After `101`, **binary** frames carry raw TCP bytes verbatim in both directions.
3. The TCP connection is dialed before the upgrade by default (timeout 10000 ms), so a
   dead target comes back as a plain HTTP `502`; `?dial=lazy` dials on the first client byte instead.
4. A WebSocket Close frame stops client→target delivery. With `allowHalfOpen`, the Worker keeps
   the target socket briefly to coordinate closure; WebSocket Close is not a general TCP half-close.
5. A zero-length keepalive frame every 25 s (clients ignore empty
   payloads) keeps edge and proxy WebSocket idle cuts from killing a quiet session.
6. Failures after `101` close the WebSocket with a reason; the `X-Relay-Session` header on the
   `101` identifies the session in the operator's logs.

## Limits and policy

- TCP only; no UDP, no inbound TCP, no HTTP forwarding (this is not a forward proxy).
- Refused by the platform on the direct road: port 25, Cloudflare IP ranges, localhost,
  private/link-local IPs. On the VPC/Gateway road the platform does not block those, so this
  relay's guards (below) and the account's Zero Trust policy are what apply.
- Guarded here: names that resolve into private space (vetted before dialing; the vetted literal is
  then dialed), internal-only suffixes, numeric hosts must be a strict dotted quad, blocked ranges
  (RFC1918, CGNAT, link-local, unique-local, multicast, 6to4, NAT64, benchmarking, documentation),
  oversized frames, idle sessions (180000 ms of payload inactivity; transport keepalives
  do not reset this), session caps (720 min /
  64 MiB). The address-based 120/minute admission brake
  applies only to unauthenticated forward WebSocket attempts and public mint
  and pair-creation attempts (separate `mint:` and `pair:` keys). Authenticated sessions,
  authenticated reverse requests, and diagnostics do not share that bucket.
- A **token is required**: `?token=<t>`, the path form `/t/<t>/connect/...` (works with clients that can only change the URL), or header `X-Relay-Token`. Any public target is allowed with a valid token.
- Cost: check current Cloudflare Workers, Durable Objects, and Workers VPC pricing before changing
  scale assumptions. The reverse relay admits explicit names only and hibernates idle sockets.

## Scope

The forward path reaches vetted public TCP targets. The reverse path pairs an authenticated
outbound-only node with an authenticated operator; the node chooses what local service to expose.
