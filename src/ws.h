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

/* One websocket connection reduced to a bidirectional byte pipe. */
typedef struct {
    Transport *t;         /* owned; closed by ws_close */
    int        is_client;
    buffer     rbuf;      /* raw bytes from the transport, not yet framed */
    buffer     pending;   /* decoded payload not yet handed to the caller */
    size_t     pending_at;
    buffer     frag;      /* continuation payload, when a frame is fragmented */
    int        frag_open;
    int        closed;
    int        close_sent;
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

/* Read payload bytes into `buf`. Returns the byte count, which is 0 both for
 * "nothing yet within the idle window" and for "closed", so *closed tells the
 * two apart. An idle ssh session is not a dead one, so this does not treat
 * silence as failure. */
int ws_read(WsSession *ws, unsigned char *buf, size_t len, int *closed);

/* Write raw bytes as one or more binary frames. */
int ws_write(WsSession *ws, const unsigned char *buf, size_t len);

/* Send a Close frame and close the transport. Safe to call twice. */
void ws_close(WsSession *ws);

/* Half-close: send a Close frame but keep the session readable, so bytes
 * already on the wire from the far end still arrive. The server exiting is
 * not the same as the session ending, and closing outright loses whatever the
 * command wrote on its way out. */
void ws_shutdown_tx(WsSession *ws);

/* One sentence naming the hop that refused. Never contains a token. */
const char *ws_strerror(const ws_status *st);

#endif /* DROPSSH_WS_H */
