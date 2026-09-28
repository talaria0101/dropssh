/* ws.h - RFC 6455 websocket framing over a dropbear Transport, and the
 * token/handshake layer the ajam relay needs.
 *
 * WHY THIS EXISTS. A cage's only egress is HTTPS on 443. An ssh client needs
 * a byte pipe to a real ssh server, and the relay gives it one inside
 * websocket binary frames. dropbear has no websocket, so this is the layer
 * that makes a relay reachable from dropbear's own process.
 *
 * IT IS A BYTE PIPE WITH A FRAMING HEADER, NOT A WEBSOCKET STACK. Binary data
 * both ways, ping/pong, close, continuation. Nothing else, because nothing
 * else is what an ssh stream is.
 *
 * MASKING IS APPLIED ON THE CLIENT SIDE AND THAT IS NOT OPTIONAL: RFC 6455
 * requires it and a spec-following server closes a connection that sends an
 * unmasked client frame. It is also why one half of this cannot serve the
 * other.
 */
#ifndef DROPSSH_WS_H
#define DROPSSH_WS_H

#include <stddef.h>
#include <stdint.h>

#include "transport.h"

#define WS_KEEPALIVE_DEFAULT_MS 20000

/* ⛔ A FRAME LARGER THAN THIS IS REFUSED, NOT ALLOCATED. The length field is
 * 63 bits wide, so one 10-byte header can ask for 8 EiB. Without a bound, a
 * peer picks the size of the allocation dropssh makes on its behalf. */
#define WS_MAX_FRAME (16u * 1024u * 1024u)

/* Why a websocket session ended. A caller that reports only "connection
 * failed" cannot be told apart from a relay that was down, and the operator
 * needs to know which hop refused. */
typedef enum {
    WS_OK = 0,
    WS_ERR_CONNECT,       /* could not reach the relay at all */
    WS_ERR_HTTP,          /* the relay answered with a status, not a 101 */
    WS_ERR_ACCEPT,        /* 101 but Sec-WebSocket-Accept did not match */
    WS_ERR_FRAME,         /* malformed framing from the peer */
    WS_ERR_TOO_BIG,       /* a frame above ws_max_frame */
    WS_ERR_CLOSED,        /* peer sent a Close frame, or the socket closed */
    WS_ERR_TIMEOUT,
    WS_ERR_OOM
} ws_err;

typedef struct {
    ws_err err;
    int    status;                        /* 0 if there was no HTTP status */
    char   detail[256];                   /* the relay's own words, if any */
} ws_status;

/* One decoded websocket message, queued in arrival order with its OWN
 * opcode. The opcode is stored per frame rather than per session because the
 * multiplexed reverse path tells a control message from session data by the
 * frame's opcode, and a decoder that reports "the last one" for every frame in
 * a coalesced read is the defect this type exists to make impossible. */
typedef struct WsFrame {
    struct WsFrame *next;
    int      opcode;
    size_t   len;
    unsigned char data[1];   /* over-allocated to len */
} WsFrame;

/* One websocket connection reduced to a bidirectional byte pipe. */
typedef struct {
    Transport *t;         /* owned; closed by ws_close */
    int        is_client;
    buffer     rbuf;      /* raw bytes from the transport, not yet framed */
    WsFrame   *fq_head;   /* decoded messages, in arrival order */
    WsFrame   *fq_tail;
    size_t     fq_count;  /* how many are queued */
    size_t     fq_bytes;  /* ⛔ the backpressure budget: see ws_set_queue_cap */
    size_t     fq_cap;    /* bytes; exceeding it closes the session */
    unsigned   max_frame;     /* ⛔ the relay's advertised maxFrameBytes */
    unsigned   max_sessions;  /* ⛔ the relay's advertised maxSessions */
    buffer     frag;      /* continuation payload, when a frame is fragmented */
    int        frag_open;
    int        frag_opcode;   /* the opcode the fragment sequence started with */
    buffer     spill;     /* ws_read's read cursor: a frame's tail, not yet handed out */
    int        closed;
    int        close_sent;
    int        close_code;     /* the peer's close code, 0 if it sent none */
    char       close_reason[124];
    char       pending_accept_key[128];  /* ⛔ between peek and accept */
    unsigned   last_tx_ms;
    unsigned   keepalive_ms;
} WsSession;

/* Mint a forward token from a relay that issues them itself:
 *   POST <base>/v1/mint with an empty body, answering {token,expires,scope}.
 *
 * THE TOKEN GOES TO THE CALLER AND NOWHERE ELSE. A token is a credential, and
 * the relay's own documentation says a token quoted on a web page, a log line
 * or an example is already compromised. This function fills `out` and does not
 * mention it again.
 *
 * `base` is an https URL with no trailing slash. Returns 0 on success. */
int dropssh_mint_token(const char *base, const char *extra_headers,
                       char *out, size_t outlen, ws_status *st);

/* ⛔ A REVERSE PAIR IS ONE HTTP CALL THAT RETURNS THREE THINGS, AND READING
 * ONLY THE TOKEN WAS THE FIRST VERSION'S BUG.
 *
 * `POST /v1/mint` answers {"token":...} and mints a FORWARD credential, so
 * `dropssh pair` built on it printed the SAME forward token twice under two
 * role labels. It looked right and was useless: a forward token is scoped to
 * one target on the forward path and is refused on /v1/node/ and
 * /v1/connect/ with 403, which reads as "no token, or the wrong token" and
 * sends an operator hunting for a typo.
 *
 * The reverse endpoint is `POST /v1/pair`, and it answers
 *
 *     {"name":..,"node_token":..,"connect_token":..,"stop_token":..,"expires":..}
 *
 * so a node and its operator each need a DIFFERENT credential, plus the name
 * they share. All three are read here. Nothing is printed except the name and
 * the two tokens; stop_token and expires are returned so a caller can revoke
 * or schedule, and neither is printed because a stop token in a terminal is a
 * way to kill someone else's session. */
typedef struct {
    char name[128];
    char node_token[1024];
    char connect_token[1024];
    char stop_token[1024];
    long long expires_ms;      /* 0 when the relay did not say */
} RelayPair;

int dropssh_request_pair(const char *base, RelayPair *out, ws_status *st);

/* Client handshake. `path` is the request target: "/connect/railway",
 * "/connect/host/port" or "/v1/connect/name". `token` may be NULL when the
 * relay requires none. On return *ws owns *t either way, so a caller has one
 * close path. */
int ws_client(Transport *t, const char *host_header, const char *path,
              const char *token, const char *user_agent,
              WsSession *ws, ws_status *st);

/* Server handshake, for `dropssh relay`. On success `request_path` holds the
 * request target, which is what the relay dispatches on. */
int ws_server(Transport *t, WsSession *ws, char *request_path,
              size_t pathlen, ws_status *st);

/* ⛔ THE SERVER HANDSHAKE IN TWO HALVES, AND THE SPLIT EXISTS SO A RELAY CAN
 * REFUSE AT THE RIGHT STATUS.
 *
 * The single-call form sends the 101 as soon as the request headers are read,
 * which leaves nothing to refuse with: by the time the caller has the request
 * target and can discover that the node is not connected, the 101 has already
 * gone out and the only honest answer left is a Close frame. That is what the
 * first version of this relay did, and an operator asking for a name with no
 * node got a successful upgrade followed immediately by a close -- which reads
 * exactly like a relay that accepted and then failed, and exits 0.
 *
 * The ajam relay answers `503 the node is not connected` on the UPGRADE
 * (measured 2026-09-28, on a pair with the node not yet connected), and that
 * is the behaviour an operator's tooling can act on. So: peek reads the
 * request and extracts the target WITHOUT answering, the caller decides, and
 * ws_server_accept sends the 101.
 *
 * Calling ws_server is exactly peek followed by accept, so a server that has
 * nothing to refuse keeps one call. */
int ws_server_peek(Transport *t, WsSession *ws, char *request_path,
                   size_t pathlen, ws_status *st);

/* ⛔ THE SAME CALL, ALSO HANDING BACK `X-Relay-Token`.
 *
 * The relay authenticates an upgrade, and the credential arrives in a header of
 * the upgrade request. `ws_server_peek` parses the header block, keeps the
 * WebSocket key and discards the rest -- and it discards it because at the time
 * it was written there was nothing else in the request worth keeping. A second
 * scan over the raw buffer is not an option, because `ws_server_peek` RESETS
 * `rbuf` at the end, so anything that re-read it afterwards reads freed or
 * reused memory. So the value is captured in the same scan that finds the key.
 *
 * `peek_token` may be NULL, in which case the token is parsed and discarded
 * exactly as before and a caller that does not authenticate sees no
 * difference. The value is bounded, truncated at the first CR or LF, and never
 * longer than the caller's buffer.
 */
int ws_server_peek_tok(Transport *t, WsSession *ws, char *request_path,
                       size_t pathlen, char *peek_token,
                       size_t peek_token_len, ws_status *st);
int ws_server_accept(WsSession *ws, ws_status *st);

/* Read payload bytes into `buf`. Returns the byte count, which is 0 both for
 * "nothing yet within the idle window" and for "closed", so *closed tells the
 * two apart. An idle ssh session is not a dead one, so this does not treat
 * silence as failure.
 *
 * ⛔ THIS IS A BYTE STREAM, NOT A FRAME READER, AND IT IS THE ONE THAT IS
 * WRONG FOR THE MULTIPLEXED PATH. It returns "whatever has arrived", so two
 * frames delivered together become one, and the caller cannot tell a control
 * message from session data. Every layer that needs message boundaries uses
 * ws_recv_frame instead. This one is kept because the forward path genuinely
 * is a byte pipe and nothing there wants boundaries. */
int ws_read(WsSession *ws, unsigned char *buf, size_t len, int *closed);

/* One FRAME, with its opcode, and the frame is consumed when it is returned.
 *
 * ⛔ THIS IS THE FIX FOR B4, AND THE TWO PROPERTIES THAT MATTER ARE BOTH IN
 * THE SIGNATURE. It consumes what it returns, so a frame cannot be handed out
 * twice; and the opcode travels WITH the frame it belongs to, so a text
 * control message coalesced with a following binary data frame is still
 * reported as text and the binary frame as binary. ws_read cannot express
 * either, which is the whole defect.
 *
 * `*opcode` is 0x1 for text and 0x2 for binary. Ping, pong and close are
 * handled inside and are never returned as frames: a ping is answered, and a
 * close is recorded in ws_close_code/ws_close_reason and reported by the
 * return value. Returns 1 when a frame was delivered, 0 when none arrived
 * within the idle window, -1 on close or fatal framing.
 *
 * The payload is COPIED into `dst` (reset first), so it is a buffer the caller
 * owns the contents of and may keep after the next call. A caller that hands in
 * a stack buffer per call and reads it before the next call is the common case
 * and the fast one. */
int ws_recv_frame(WsSession *ws, int *opcode, buffer *dst, size_t *len,
                  int *closed, int *fatal);

/* ⛔ THE NON-BLOCKING FORM, AND IT EXISTS BECAUSE ws_recv_frame STARVES STDIN.
 * ws_recv_frame waits for a frame for as long as it takes, looping on the
 * transport with a 20 ms sleep. A multiplexed operator ALSO has to service
 * stdin, and when the two share a loop the blocking read wins: the operator
 * read 2000 bytes of a 3658-byte stream and then sat in ws_recv_frame waiting
 * for a frame the node had not sent yet, while the rest of the stream sat in
 * a pipe. The session is then a hang with every log line correct, which is
 * the worst shape a framing bug can take.
 *
 * This variant returns 1 if a frame was ready, 0 if nothing is queued RIGHT
 * NOW, and -1 on close or fatal. It reads from the transport only if bytes
 * are already buffered; it never blocks. The caller owns the wait. */
int ws_poll_frame(WsSession *ws, int *opcode, buffer *dst, size_t *len,
                  int *closed, int *fatal);

/* ⛔ WHY A PEER'S CLOSE IS SURFACED AT ALL. Measured 2026-09-28: a node that
 * sends a frame without the 32-hex id prefix is closed by the relay with code
 * 1009 "bad multiplex frame", and the operator's socket is then closed with
 * 1011 "node disconnected". A client that reports only "connection closed"
 * cannot tell its own framing bug from the relay being down, which is exactly
 * the B11 failure that the docs used to describe as silence. */
int         ws_close_code(const WsSession *ws);
const char *ws_close_reason(const WsSession *ws);

/* ⛔ BOUNDED QUEUES, AS POLICY NUMBERS RATHER THAN AS HINTS. B7 said nothing
 * bounded an in-flight queue; these are the bounds. A queue over its byte cap
 * closes the session rather than growing, because the alternative is a fast
 * peer choosing how much memory this process allocates on its behalf. The
 * session cap is enforced by the caller, which owns the sessions. */
#define WS_DEFAULT_QUEUE_BYTES (4u * 1024u * 1024u)
void ws_set_queue_cap(WsSession *ws, size_t bytes);

/* ⛔ THE RELAY'S TWO ADVERTISED LIMITS, HONOURED. A relay states
 * maxFrameBytes and maxSessions in its `hello` and this implementation
 * enforced neither. The write path now refuses to build a frame larger than
 * max_frame and the multiplexer refuses to open more than max_sessions, so
 * the node cannot be closed by a relay for breaking a promise it made. */
#define WS_HELLO_DEFAULT_FRAME 65536u
#define WS_HELLO_DEFAULT_SESSIONS 64u
int  ws_set_limits(WsSession *ws, unsigned max_frame, unsigned max_sessions);
unsigned ws_max_frame(const WsSession *ws);
unsigned ws_max_sessions(const WsSession *ws);

/* Write raw bytes as one or more binary frames. */
int ws_write(WsSession *ws, const unsigned char *buf, size_t len);

/* ⛔ CONTROL MESSAGES GO OUT AS TEXT, AND THIS IS A SEPARATE ENTRY POINT ON
 * PURPOSE. The relay's reverse path tells a control message from session data
 * by the FRAME OPCODE: text is control, binary is data, and a text frame where
 * data was required is closed with 1003 "binary frames required" (measured
 * 2026-09-28 against tcp.ssh.relay.ajam.dev). Sending the JSON through
 * ws_write would make the opcode a caller's decision, and one caller would get
 * it wrong. */
int ws_write_text(WsSession *ws, const unsigned char *buf, size_t len);

/* ⛔ MOVE OWNERSHIP, AND NEVER COPY A WsSession. See ws_move for the full
 * reason: a copy of a session shares its buffer pointers, and the first close
 * frees what the second still points at.
 *
 * `*src` is left INERT -- no transport, no buffers -- so a `ws_close(src)` after
 * the move is a no-op rather than a second free. That property is what makes it
 * safe to keep the existing `ws_close(&ws)` on refusal paths that sit above
 * this call, and it is what stops a refusal added BELOW it from reintroducing
 * the aliasing. `docs/relay-issues.md` U2. */
void ws_move(WsSession *dst, WsSession *src);

/* Send a Close frame and close the transport. Safe to call twice, and safe to
 * call on a session that has been moved away from. */
void ws_close(WsSession *ws);

/* Send a Close frame carrying `code` and `reason`. ⛔ THE REASON IS THE
 * DIAGNOSIS, AND A CLOSE WITHOUT ONE IS HOW B11 COST AN AFTERNOON. The relay
 * names its refusals ("node open timeout", "binary frames required", "bad
 * multiplex frame") and a node that cannot say which hop refused is a node
 * whose operator is guessing. The reason is truncated to 120 bytes, which is
 * the control frame's own limit. */
void ws_close_with(WsSession *ws, int code, const char *reason);

/* Half-close: send a Close frame but keep the session readable, so bytes
 * already on the wire from the far end still arrive. The server exiting is
 * not the same as the session ending, and closing outright loses whatever the
 * command wrote on its way out. */
void ws_shutdown_tx(WsSession *ws);

/* One sentence naming the hop that refused. Never contains a token. */
const char *ws_strerror(const ws_status *st);

#endif /* DROPSSH_WS_H */
