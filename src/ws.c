/* ws.c - RFC 6455 framing, the relay handshake, and the token mint.
 *
 * See ws.h for why this exists and what it deliberately is not.
 */
#include "ws.h"
#include "tls.h"
#include "util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static unsigned now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (unsigned)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

static void st_set(ws_status *st, ws_err e, int status, const char *fmt, ...) {
    if (st == NULL) {
        return;
    }
    st->err = e;
    st->status = status;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(st->detail, sizeof st->detail, fmt, ap);
    va_end(ap);
}

const char *ws_strerror(const ws_status *st) {
    static char out[512];
    if (st == NULL) {
        return "no status";
    }
    if (st->detail[0]) {
        snprintf(out, sizeof out, "%s", st->detail);
    } else {
        snprintf(out, sizeof out, "%s", "websocket session failed");
    }
    return out;
}

/* ------------------------------------------------------------------ mint */
int dropssh_mint_token(const char *base, const char *extra_headers,
                       char *out, size_t outlen, ws_status *st) {
    char host[256] = "";
    int port = 443;
    const char *h = base;
    if (strncmp(h, "https://", 8) == 0) {
        h += 8;
    }
    size_t o = 0;
    while (h[o] && h[o] != '/' && h[o] != ':' && o < sizeof host - 1) {
        host[o] = h[o];
        o++;
    }
    host[o] = 0;
    if (h[o] == ':') {
        port = atoi(h + o + 1);
        if (port <= 0) {
            port = 443;
        }
    }
    char *body = NULL;
    size_t len = 0;
    char err[256] = "";
    const char *ph = dropssh_proxy_host();
    int pp = dropssh_proxy_port();
    if (tls_post(host, port, "/v1/mint", "{}", 1, dropssh_insecure(),
                 ph, pp, &body, &len, err, sizeof err) != 0) {
        st_set(st, WS_ERR_CONNECT, 0, "%s", err);
        return -1;
    }
    /* ⛔ THE JSON IS READ WITH A SCAN, NOT A PARSER, AND THE SCAN IS
     * DELIBERATE. The answer is {"token":..,"expires":..,"scope":..} and the
     * only field dropssh needs is the token. A JSON parser is a large surface
     * fed by a network, for one string. The scan takes the text between
     * "token" and the next quote and nothing else, so a hostile body with
     * forty kilobytes of JSON cannot use it to make dropssh allocate or loop.
     *
     * ⛔ AND THE RESULT IS COPIED INTO A FIXED BUFFER AND VALIDATED FOR
     * LENGTH, because it becomes a header value. A token is short and
     * structured ("ephm1.<exp>.<scope>.<mac>"); anything longer, or carrying
     * a newline, is refused rather than sent, because a newline in a header
     * value is a second header. */
    const char *k = strstr(body, "\"token\"");
    if (k == NULL) {
        free(body);
        st_set(st, WS_ERR_HTTP, 200, "the relay's mint answer had no token field");
        return -1;
    }
    const char *q = strchr(k + 7, '"');
    if (q == NULL) {
        free(body);
        st_set(st, WS_ERR_HTTP, 200, "the relay's mint answer was truncated");
        return -1;
    }
    const char *q2 = strchr(q + 1, '"');
    if (q2 == NULL) {
        free(body);
        st_set(st, WS_ERR_HTTP, 200, "the relay's mint answer was truncated");
        return -1;
    }
    size_t tl = (size_t)(q2 - q - 1);
    if (tl == 0 || tl >= outlen) {
        free(body);
        st_set(st, WS_ERR_HTTP, 200, "the relay minted a token of an unusable length");
        return -1;
    }
    memcpy(out, q + 1, tl);
    out[tl] = 0;
    for (size_t i = 0; i < tl; i++) {
        unsigned char c = (unsigned char)out[i];
        if (c == '\r' || c == '\n' || c < 0x20 || c == 0x7f) {
            memset(out, 0, outlen);
            free(body);
            st_set(st, WS_ERR_HTTP, 200,
                   "the relay minted a token containing a control character, "
                   "which cannot be sent as a header value");
            return -1;
        }
    }
    free(body);
    if (st) {
        st->err = WS_OK;
        st->status = 200;
        st->detail[0] = 0;
    }
    (void)extra_headers;
    return 0;
}

/* ------------------------------------------------------------- handshakes */
static int check_accept(const char *headers, const char *key, char *err,
                        size_t errlen) {
    char expect[64];
    dropssh_ws_accept(key, expect, sizeof expect);
    /* ⛔ THE COMPARISON IS A SUBSTRING SEARCH AND THAT IS CORRECT HERE. The
     * value is base64 of 20 bytes, so it is 28 characters with no padding
     * ambiguity and no chance of appearing as a substring of another value.
     * A constant-time compare would be theatre here: the thing being compared
     * is a public value from a public handshake, and there is no secret to
     * leak by timing. */
    if (strstr(headers, expect) == NULL) {
        snprintf(err, errlen,
                 "the relay answered 101 but its Sec-WebSocket-Accept did not "
                 "match the key that was sent, so this is not a websocket peer");
        return -1;
    }
    return 0;
}

static int http_status(const char *headers) {
    if (headers == NULL || strncmp(headers, "HTTP/1.", 7) != 0) {
        return 0;
    }
    const char *sp = strchr(headers, ' ');
    if (sp == NULL) {
        return 0;
    }
    return atoi(sp + 1);
}

int ws_client(Transport *t, const char *host_header, const char *path,
              const char *token, const char *user_agent,
              WsSession *ws, ws_status *st) {
    memset(ws, 0, sizeof *ws);
    ws->t = t;
    ws->is_client = 1;
    ws->keepalive_ms = WS_KEEPALIVE_DEFAULT_MS;
    buf_init(&ws->rbuf);
    buf_init(&ws->pending);
    buf_init(&ws->frag);

    char key[64];
    dropssh_random_b64(key, sizeof key, 16);

    char req[2048];
    int n = snprintf(req, sizeof req,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "User-Agent: %s\r\n"
                     "%s"
                     "\r\n",
                     path, host_header, key,
                     user_agent ? user_agent : "dropssh",
                     token ? "" : "");
    if (n < 0 || (size_t)n >= sizeof req) {
        st_set(st, WS_ERR_CONNECT, 0, "the relay request is too long to build");
        return -1;
    }
    /* ⛔ THE TOKEN GOES IN A HEADER, NOT IN THE PATH, AND THE PATH FORM IS
     * NOT USED EVEN THOUGH THE RELAY ACCEPTS IT. The relay's own
     * documentation says to use `?token=` or `/t/<t>/...` only when headers
     * are unavailable, because a URL is written to every access log on the
     * way and a header is not. dropssh can always send a header, so it does,
     * and a relay session's URL is therefore safe to log. */
    if (token && *token) {
        char hv[1024];
        int hn = snprintf(hv, sizeof hv, "X-Relay-Token: %s\r\n", token);
        if (hn < 0 || (size_t)hn >= sizeof hv) {
            st_set(st, WS_ERR_CONNECT, 0, "the token is too long to send as a header");
            return -1;
        }
        n = snprintf(req, sizeof req,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "User-Agent: %s\r\n"
                     "%s"
                     "\r\n",
                     path, host_header, key,
                     user_agent ? user_agent : "dropssh", hv);
        if (n < 0 || (size_t)n >= sizeof req) {
            st_set(st, WS_ERR_CONNECT, 0, "the relay request is too long to build");
            return -1;
        }
    }
    if (t->write(t, req, (size_t)n) != 0) {
        st_set(st, WS_ERR_CONNECT, 0, "could not write the relay request: %s",
               t->name);
        return -1;
    }

    /* Read the response headers. A relay that is refusing answers fast, so a
     * short window is right for the refusal and wrong for the 101's first
     * frame, which is why the read stops at the header break and the framing
     * loop below takes over. */
    unsigned start = now_ms();
    unsigned waited = 0;
    while (ws->rbuf.len < 1 || memmem(ws->rbuf.p, ws->rbuf.len, "\r\n\r\n", 4) == NULL) {
        if (waited > 20000) {
            st_set(st, WS_ERR_TIMEOUT, 0,
                   "the relay did not answer the websocket upgrade within 20s");
            return -1;
        }
        unsigned char tmp[4096];
        size_t got = 0;
        int eof = 0;
        if (t->read(t, tmp, sizeof tmp, &got, &eof) != 0) {
            st_set(st, WS_ERR_CONNECT, 0, "the relay connection failed: %s", t->name);
            return -1;
        }
        if (got) {
            buf_append(&ws->rbuf, tmp, got);
            waited = 0;
            continue;
        }
        if (eof) {
            st_set(st, WS_ERR_CONNECT, 0,
                   "the relay closed the connection during the websocket upgrade");
            return -1;
        }
        unsigned elapsed = now_ms() - start;
        if (elapsed - waited >= 250) {
            waited = elapsed;
            dropssh_sleep_ms(50);
        }
    }

    unsigned char *brk = memmem(ws->rbuf.p, ws->rbuf.len, "\r\n\r\n", 4);
    size_t hlen = (size_t)(brk - ws->rbuf.p) + 4;
    char *headers = malloc(hlen + 1);
    if (headers == NULL) {
        st_set(st, WS_ERR_OOM, 0, "out of memory reading the relay's answer");
        return -1;
    }
    memcpy(headers, ws->rbuf.p, hlen);
    headers[hlen] = 0;
    size_t rest = ws->rbuf.len - hlen;
    unsigned char *restp = NULL;
    if (rest) {
        restp = malloc(rest);
        if (restp == NULL) {
            free(headers);
            st_set(st, WS_ERR_OOM, 0, "out of memory");
            return -1;
        }
        memcpy(restp, ws->rbuf.p + hlen, rest);
    }
    buf_reset(&ws->rbuf);
    if (rest) {
        buf_append(&ws->rbuf, restp, rest);
        free(restp);
    }

    int status = http_status(headers);
    if (status != 101) {
        /* ⛔ THE RELAY'S OWN STATUS LINE IS PASSED THROUGH, AND 403 AND 502
         * ARE CALLED OUT BY NAME. A 403 means the token is absent or wrong and
         * a 502 means the target would not answer, and those two need opposite
         * things from the operator: mint again, or wait for the target. A
         * message that says "upgrade refused" for both costs a session. */
        const char *why = "";
        if (status == 403) {
            why = ": no token, or the wrong token. Mint a fresh one with "
                  "--mint, or set one with --token";
        } else if (status == 502) {
            why = ": the relay could not reach the target";
        } else if (status == 401) {
            why = ": the relay wants a credential this client did not send";
        }
        st_set(st, WS_ERR_HTTP, status, "relay refused the upgrade with HTTP %d%s",
               status, why);
        free(headers);
        return -1;
    }
    if (check_accept(headers, key, st->detail, sizeof st->detail) != 0) {
        st->err = WS_ERR_ACCEPT;
        st->status = 101;
        free(headers);
        return -1;
    }
    free(headers);
    ws->last_tx_ms = now_ms();
    if (st) {
        st->err = WS_OK;
        st->detail[0] = 0;
    }
    return 0;
}

int ws_server(Transport *t, WsSession *ws, char *request_path,
              size_t pathlen, ws_status *st) {
    memset(ws, 0, sizeof *ws);
    ws->t = t;
    ws->is_client = 0;
    ws->keepalive_ms = WS_KEEPALIVE_DEFAULT_MS;
    buf_init(&ws->rbuf);
    buf_init(&ws->pending);
    buf_init(&ws->frag);

    unsigned start = now_ms(), waited = 0;
    while (ws->rbuf.len < 1 || memmem(ws->rbuf.p, ws->rbuf.len, "\r\n\r\n", 4) == NULL) {
        if (waited > 20000) {
            st_set(st, WS_ERR_TIMEOUT, 0, "no websocket upgrade within 20s");
            return -1;
        }
        unsigned char tmp[4096];
        size_t got = 0;
        int eof = 0;
        if (t->read(t, tmp, sizeof tmp, &got, &eof) != 0 || (got == 0 && eof)) {
            st_set(st, WS_ERR_CONNECT, 0, "peer closed during the websocket upgrade");
            return -1;
        }
        if (got) {
            buf_append(&ws->rbuf, tmp, got);
            waited = 0;
            continue;
        }
        unsigned elapsed = now_ms() - start;
        if (elapsed - waited >= 250) {
            waited = elapsed;
            dropssh_sleep_ms(50);
        }
    }
    unsigned char *brk = memmem(ws->rbuf.p, ws->rbuf.len, "\r\n\r\n", 4);
    size_t hlen = (size_t)(brk - ws->rbuf.p) + 4;
    char *headers = malloc(hlen + 1);
    if (headers == NULL) {
        st_set(st, WS_ERR_OOM, 0, "out of memory");
        return -1;
    }
    memcpy(headers, ws->rbuf.p, hlen);
    headers[hlen] = 0;

    /* the request target: "GET /connect/railway HTTP/1.1" */
    const char *sp = strchr(headers, ' ');
    const char *sp2 = sp ? strchr(sp + 1, ' ') : NULL;
    if (sp == NULL || sp2 == NULL) {
        free(headers);
        st_set(st, WS_ERR_HTTP, 0, "the request line was not parseable");
        return -1;
    }
    size_t plen = (size_t)(sp2 - sp - 1);
    if (plen >= pathlen) {
        plen = pathlen - 1;
    }
    memcpy(request_path, sp + 1, plen);
    request_path[plen] = 0;
    char *q = strchr(request_path, '?');
    if (q) {
        *q = 0;
    }

    const char *k = NULL;
    {
        /* case-insensitive header scan, bounded to the header block */
        char *line = strstr(headers, "\r\n");
        while (line) {
            line += 2;
            if (strncasecmp(line, "Sec-WebSocket-Key:", 18) == 0) {
                k = line + 18;
                while (*k == ' ') {
                    k++;
                }
                break;
            }
            char *nx = strstr(line, "\r\n");
            if (nx == NULL) {
                break;
            }
            line = nx;
        }
    }
    if (k == NULL) {
        free(headers);
        st_set(st, WS_ERR_HTTP, 0, "no Sec-WebSocket-Key in the upgrade request");
        return -1;
    }
    char key[128];
    size_t ki = 0;
    while (k[ki] && k[ki] != '\r' && k[ki] != '\n' && ki < sizeof key - 1) {
        key[ki] = k[ki];
        ki++;
    }
    key[ki] = 0;

    char accept[64];
    dropssh_ws_accept(key, accept, sizeof accept);
    char resp[256];
    int rn = snprintf(resp, sizeof resp,
                      "HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
    free(headers);
    if (rn < 0 || (size_t)rn >= sizeof resp) {
        st_set(st, WS_ERR_CONNECT, 0, "the 101 response is too long to build");
        return -1;
    }
    if (t->write(t, resp, (size_t)rn) != 0) {
        st_set(st, WS_ERR_CONNECT, 0, "could not write the 101 response");
        return -1;
    }

    /* anything after the header block is already-framed bytes */
    size_t rest = ws->rbuf.len - hlen;
    unsigned char *restp = NULL;
    if (rest) {
        restp = malloc(rest);
        if (restp) {
            memcpy(restp, ws->rbuf.p + hlen, rest);
        }
    }
    buf_reset(&ws->rbuf);
    if (restp) {
        buf_append(&ws->rbuf, restp, rest);
        free(restp);
    }
    ws->last_tx_ms = now_ms();
    if (st) {
        st->err = WS_OK;
        st->detail[0] = 0;
    }
    return 0;
}

/* ----------------------------------------------------------------- framing */
static int send_frame(WsSession *ws, int opcode, const unsigned char *pl,
                      size_t len) {
    unsigned char hdr[14];
    size_t hl = 0;
    hdr[hl++] = (unsigned char)(0x80 | opcode);
    int mask = ws->is_client;
    if (len < 126) {
        hdr[hl++] = (unsigned char)(len | (mask ? 0x80 : 0));
    } else if (len < 65536) {
        hdr[hl++] = (unsigned char)((mask ? 0x80 : 0) | 126);
        hdr[hl++] = (unsigned char)(len >> 8);
        hdr[hl++] = (unsigned char)(len);
    } else {
        hdr[hl++] = (unsigned char)((mask ? 0x80 : 0) | 127);
        for (int i = 7; i >= 0; i--) {
            hdr[hl++] = (unsigned char)((uint64_t)len >> (i * 8));
        }
    }
    unsigned char maskkey[4] = { 0, 0, 0, 0 };
    if (mask) {
        dropssh_random(maskkey, 4);
        memcpy(hdr + hl, maskkey, 4);
        hl += 4;
    }
    if (ws->t->write(ws->t, hdr, hl) != 0) {
        return -1;
    }
    if (len) {
        /* ⛔ THE PAYLOAD IS MASKED IN PLACE IN A BUFFER OF ITS OWN RATHER THAN
         * IN A SECOND WRITE. A masking key is applied to the whole frame, so
         * splitting the write would produce two frames' worth of bytes under
         * one key if the far end reassembled by length rather than by FIN. */
        unsigned char *body = malloc(len);
        if (body == NULL) {
            return -1;
        }
        if (mask) {
            for (size_t i = 0; i < len; i++) {
                body[i] = pl[i] ^ maskkey[i & 3];
            }
        } else {
            memcpy(body, pl, len);
        }
        int rc = ws->t->write(ws->t, body, len);
        free(body);
        if (rc != 0) {
            return -1;
        }
    }
    ws->last_tx_ms = now_ms();
    return 0;
}

int ws_write(WsSession *ws, const unsigned char *buf, size_t len) {
    if (ws->closed) {
        return -1;
    }
    size_t off = 0;
    /* ⛔ ONE FRAME PER WRITE, UP TO 64 KiB, NOT ONE FRAME FOR THE WHOLE
     * STREAM. The relay documents a 64 KiB session cap on frame size and
     * drops oversized frames, and a 40 MiB scp is one write at the syscall
     * level. Chunking here means a large transfer is a series of legal
     * frames instead of one that the far end refuses. */
    const size_t CHUNK = 65536;
    while (off < len) {
        size_t n = len - off;
        if (n > CHUNK) {
            n = CHUNK;
        }
        if (send_frame(ws, 2, buf + off, n) != 0) {
            return -1;
        }
        off += n;
    }
    return 0;
}

/* A half-close: tell the peer this side is done sending, and leave the
 * session readable. Used when the ssh server has exited and its output is on
 * the wire, so the far end sees the end of the stream rather than a cut. */
void ws_shutdown_tx(WsSession *ws) {
    if (ws == NULL || ws->close_sent) {
        return;
    }
    send_frame(ws, 0x8, NULL, 0);
    ws->close_sent = 1;
}

void ws_close(WsSession *ws) {
    if (ws == NULL) {
        return;
    }
    if (ws->t && !ws->close_sent) {
        send_frame(ws, 8, NULL, 0);
        ws->close_sent = 1;
    }
    if (ws->t) {
        ws->t->close(ws->t);
        ws->t = NULL;
    }
    buf_free(&ws->rbuf);
    buf_free(&ws->pending);
    buf_free(&ws->frag);
}

static int read_more(WsSession *ws, int *eof) {
    unsigned char tmp[16384];
    size_t got = 0;
    *eof = 0;
    if (ws->t == NULL) {
        *eof = 1;
        return 0;
    }
    if (ws->t->read(ws->t, tmp, sizeof tmp, &got, eof) != 0) {
        return -1;
    }
    if (got) {
        return buf_append(&ws->rbuf, tmp, got);
    }
    return 0;
}

/* Decode as many frames as the buffer holds. Returns 0, or -1 with ws->closed
 * set for a Close frame, or -1 with ws->rbuf poisoned on malformed framing. */
static int decode_available(WsSession *ws, int *fatal) {
    *fatal = 0;
    for (;;) {
        unsigned char *b = ws->rbuf.p + ws->rbuf.at;
        size_t have = ws->rbuf.len;
        if (have < 2) {
            return 0;
        }
        int fin = (b[0] & 0x80) != 0;
        int opcode = b[0] & 0x0f;
        int masked = (b[1] & 0x80) != 0;
        uint64_t len = b[1] & 0x7f;
        size_t idx = 2;
        if (len == 126) {
            if (have < 4) {
                return 0;
            }
            len = ((uint64_t)b[2] << 8) | b[3];
            idx = 4;
        } else if (len == 127) {
            if (have < 10) {
                return 0;
            }
            len = 0;
            for (int i = 0; i < 8; i++) {
                len = (len << 8) | b[2 + i];
            }
            idx = 10;
        }
        /* ⛔ THE DECLARED LENGTH IS CHECKED AGAINST A BOUND BEFORE ANY
         * ALLOCATION IS ATTEMPTED. A peer can put 2^63-1 in a 10-byte header,
         * and `have` will never reach it, so the loop would spin until the
         * process died. The bound is the relay's own 16 MiB frame policy; a
         * frame above it is a peer that is not this relay. */
        if (len > (uint64_t)WS_MAX_FRAME) {
            *fatal = 1;
            ws->closed = 1;
            return -1;
        }
        unsigned char mk[4] = { 0, 0, 0, 0 };
        if (masked) {
            if (have < idx + 4) {
                return 0;
            }
            memcpy(mk, b + idx, 4);
            idx += 4;
        }
        if (have < idx + len) {
            return 0;
        }
        unsigned char *pl = b + idx;
        if (masked) {
            for (uint64_t i = 0; i < len; i++) {
                pl[i] ^= mk[i & 3];
            }
        }
        size_t plen = (size_t)len;

        if (opcode == 0x8) {          /* close */
            buf_consume(&ws->rbuf, idx + plen);
            ws->closed = 1;
            return -1;
        }
        if (opcode == 0x9) {          /* ping -> pong, same payload */
            send_frame(ws, 0xA, pl, plen);
            buf_consume(&ws->rbuf, idx + plen);
            continue;
        }
        if (opcode == 0xA) {          /* pong */
            buf_consume(&ws->rbuf, idx + plen);
            continue;
        }
        if (opcode == 0x0) {          /* continuation */
            if (!ws->frag_open) {
                *fatal = 1;
                ws->closed = 1;
                return -1;
            }
            if (buf_append(&ws->frag, pl, plen) != 0) {
                *fatal = 1;
                ws->closed = 1;
                return -1;
            }
            buf_consume(&ws->rbuf, idx + plen);
            if (fin) {
                if (buf_append(&ws->pending, ws->frag.p, ws->frag.len) != 0) {
                    *fatal = 1;
                    ws->closed = 1;
                    return -1;
                }
                buf_reset(&ws->frag);
                ws->frag_open = 0;
            }
            continue;
        }
        /* 0x1 text, 0x2 binary. ssh bytes are binary; a text frame from this
         * relay would be a protocol error upstream, and the bytes are passed
         * through so the ssh layer above reports it in ssh's own terms. */
        if (!ws->frag_open) {
            if (buf_append(&ws->pending, pl, plen) != 0) {
                *fatal = 1;
                ws->closed = 1;
                return -1;
            }
        } else {
            if (buf_append(&ws->frag, pl, plen) != 0) {
                *fatal = 1;
                ws->closed = 1;
                return -1;
            }
        }
        buf_consume(&ws->rbuf, idx + plen);
        if (fin) {
            if (ws->frag_open) {
                if (buf_append(&ws->pending, ws->frag.p, ws->frag.len) != 0) {
                    *fatal = 1;
                    ws->closed = 1;
                    return -1;
                }
                buf_reset(&ws->frag);
                ws->frag_open = 0;
            }
        } else {
            ws->frag_open = 1;
        }
    }
}

int ws_read(WsSession *ws, unsigned char *buf, size_t len, int *closed) {
    *closed = 0;
    if (len == 0) {
        return 0;
    }
    for (;;) {
        if (ws->pending.len > ws->pending_at) {
            size_t n = ws->pending.len - ws->pending_at;
            if (n > len) {
                n = len;
            }
            memcpy(buf, ws->pending.p + ws->pending_at, n);
            buf_consume(&ws->pending, n);
            return (int)n;
        }
        if (ws->closed) {
            *closed = 1;
            return 0;
        }
        int fatal = 0;
        if (decode_available(ws, &fatal) != 0) {
            *closed = 1;
            if (fatal) {
                return -1;
            }
            return 0;
        }
        if (ws->pending.len > ws->pending_at) {
            continue;
        }
        int eof = 0;
        if (read_more(ws, &eof) != 0) {
            ws->closed = 1;
            *closed = 1;
            return -1;
        }
        if (eof) {
            ws->closed = 1;
            *closed = 1;
            return 0;
        }
        /* ⛔ SILENCE IS NOT AN ERROR AND IS NOT A CLOSE. The relay sends a
         * zero-length keepalive every 25 s and an ssh session can go quiet
         * for minutes while someone reads. Reporting either as "connection
         * lost" kills a working session, so the loop yields and retries, and
         * the keepalive below is what stops an intermediate from cutting a
         * quiet one instead. */
        unsigned now = now_ms();
        if (ws->keepalive_ms && now - ws->last_tx_ms >= ws->keepalive_ms) {
            send_frame(ws, 0x9, NULL, 0);
        }
        dropssh_sleep_ms(20);
    }
}
