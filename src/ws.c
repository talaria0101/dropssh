/* ws.c - RFC 6455 framing, the relay handshake, and the token mint.
 *
 * See ws.h for why this exists and what it deliberately is not.
 */
#include "ws.h"
#include "tls.h"
#include "util.h"
#include <stdlib.h>

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

/* ⛔ THE SCAN IS THE SAME BOUNDED SCAN relayproto.c USES, NOT strstr plus
 * atoi, AND THE SAME LENGTH AND CHARACTER RULES APPLY. A relay that answers
 *
 *     {"name":"x","node_token":"<4 KiB of hex>","connect_token":"y"}
 *
 * must not be able to make this process allocate, and a value carrying a
 * newline must not become a header. The scan is position-independent because
 * the one in relayproto.c was not, and that version read "," for a value and
 * reported a perfectly good hello as unparseable. */
static int body_field(const char *body, const char *key, char *out, size_t outlen) {
    out[0] = 0;
    const char *k = strstr(body, key);
    if (k == NULL) {
        return -1;
    }
    k += strlen(key);
    while (*k == ' ' || *k == '\t' || *k == '\n' || *k == '\r') {
        k++;
    }
    if (*k != ':') {
        return -1;
    }
    k++;
    while (*k == ' ' || *k == '\t' || *k == '\n' || *k == '\r') {
        k++;
    }
    if (*k != '"') {
        return -1;
    }
    k++;
    const char *e = k;
    while (*e && *e != '"') {
        if (*e == '\\' && e[1]) {
            e += 2;
            continue;
        }
        e++;
    }
    if (*e != '"') {
        return -1;
    }
    size_t n = (size_t)(e - k);
    if (n == 0 || n >= outlen) {
        return -1;
    }
    memcpy(out, k, n);
    out[n] = 0;
    /* ⛔ A CREDENTIAL IS VALIDATED BEFORE IT IS USED, NOT AFTER. These become
     * header values, and a newline in a header value is a second header. */
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)out[i];
        if (c < 0x20 || c == 0x7f) {
            memset(out, 0, outlen);
            return -1;
        }
    }
    return 0;
}

int dropssh_request_pair(const char *base, RelayPair *out, ws_status *st) {
    if (out == NULL) {
        st_set(st, WS_ERR_CONNECT, 0, "no output for the pair");
        return -1;
    }
    memset(out, 0, sizeof *out);

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
    if (tls_post(host, port, "/v1/pair", "{}", 1, dropssh_insecure(),
                 ph, pp, &body, &len, err, sizeof err) != 0) {
        st_set(st, WS_ERR_CONNECT, 0, "%s", err);
        return -1;
    }
    /* ⛔ ALL THREE OF name, node_token and connect_token ARE REQUIRED, AND A
     * MISSING ONE IS AN ERROR RATHER THAN AN EMPTY STRING. A pair with an
     * empty node_token is a cage that registers with no credential and an
     * operator holding "" -- and the symptom is a 403 on one side and a
     * working session on the other, which is the hardest version of this to
     * diagnose. Refusing here says which field the relay did not send. */
    if (body_field(body, "\"name\"", out->name, sizeof out->name) != 0) {
        free(body);
        st_set(st, WS_ERR_HTTP, 200, "the relay's pair answer had no name");
        return -1;
    }
    if (body_field(body, "\"node_token\"", out->node_token,
                   sizeof out->node_token) != 0) {
        free(body);
        st_set(st, WS_ERR_HTTP, 200,
               "the relay's pair answer had no node_token, so a cage could not "
               "register with it");
        return -1;
    }
    if (body_field(body, "\"connect_token\"", out->connect_token,
                   sizeof out->connect_token) != 0) {
        memset(out->node_token, 0, sizeof out->node_token);
        free(body);
        st_set(st, WS_ERR_HTTP, 200,
               "the relay's pair answer had no connect_token, so no operator "
               "could reach the node with it");
        return -1;
    }
    /* stop_token and expires are optional: a rendezvous relay that issues no
     * revocable credential is still a working rendezvous. A missing one is
     * zero, and a caller that prints it says "not issued". */
    if (body_field(body, "\"stop_token\"", out->stop_token,
                   sizeof out->stop_token) != 0) {
        out->stop_token[0] = 0;
    }
    {
        /* ⛔ `expires` IS A BARE NUMBER, NOT A QUOTED STRING, and the field
         * scan above requires quotes because every credential is quoted. A
         * quoted-only scan silently finds no expires and the pair prints
         * without a lifetime, which reads as "this never expires" and is the
         * opposite of true. So this one field is read as an unquoted value,
         * with the same bound and the same digit-only rule. */
        const char *e = strstr(body, "\"expires\"");
        if (e != NULL) {
            e = strchr(e, ':');
            if (e != NULL) {
                e++;
                while (*e == ' ' || *e == '\t') {
                    e++;
                }
                char digits[24];
                size_t n = 0;
                while (e[n] >= '0' && e[n] <= '9' && n < sizeof digits - 1) {
                    digits[n] = e[n];
                    n++;
                }
                digits[n] = 0;
                if (n > 0) {
                    out->expires_ms = strtoll(digits, NULL, 10);
                }
            }
        }
    }
    free(body);
    if (st) {
        st->err = WS_OK;
        st->status = 200;
        st->detail[0] = 0;
    }
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
    ws->fq_cap = WS_DEFAULT_QUEUE_BYTES;
    ws->max_frame = WS_HELLO_DEFAULT_FRAME;
    ws->max_sessions = WS_HELLO_DEFAULT_SESSIONS;
    buf_init(&ws->rbuf);
    buf_init(&ws->frag);
    buf_init(&ws->spill);

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
        /* ⛔ THE REFUSAL BODY IS READ, AND IT IS READ AFTER THE STATUS IS
         * KNOWN. A client that stops at the header break has the number and
         * not the sentence, and every non-101 from this relay family carries a
         * sentence that says which of several different problems it is. The
         * wait is short and bounded: the relay writes the whole refusal in
         * one write, so the body is already in flight, and a body that never
         * arrives must not turn a refusal into a hang. */
        size_t want = 0;
        const char *cl = strstr(headers, "Content-Length:");
        if (cl != NULL) {
            want = (size_t)atol(cl + 15);
            if (want > 512) {
                want = 512;
            }
        }
        unsigned bstart = now_ms();
        while (ws->rbuf.len < want && now_ms() - bstart < 1500) {
            unsigned char tmp[1024];
            size_t got = 0;
            int eof = 0;
            if (t->read(t, tmp, sizeof tmp, &got, &eof) != 0) {
                break;
            }
            if (got) {
                buf_append(&ws->rbuf, tmp, got);
                continue;
            }
            if (eof) {
                break;
            }
            dropssh_sleep_ms(20);
        }
        /* Whatever arrived after the header break is the body. */
        size_t bl = ws->rbuf.len;
        if (bl > 200) {
            bl = 200;
        }
        for (size_t i = 0; i < bl; i++) {
            if (ws->rbuf.p[i] == '\r' || ws->rbuf.p[i] == '\n') {
                ws->rbuf.p[i] = ' ';
            } else if (ws->rbuf.p[i] < 0x20 || ws->rbuf.p[i] == 0x7f) {
                ws->rbuf.p[i] = '.';
            }
        }
        while (bl > 0 && ws->rbuf.p[bl - 1] == ' ') {
            bl--;
        }
        if (bl > 0) {
            st->detail[0] = 0;
            snprintf(st->detail, sizeof st->detail, "%.*s", (int)bl,
                     (const char *)ws->rbuf.p);
        }
        buf_reset(&ws->rbuf);
    }
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
        } else if (status == 503 || status == 409) {
            /* ⛔ 503 AND 409 ARE PASSED THROUGH WITH THE RELAY'S OWN SENTENCE,
             * because they have different causes that ask opposite things of
             * the operator. 503 from a rendezvous is "the node is not
             * connected" (start it, or wait for it to dial in); 503 from a full
             * relay is "come back later"; 409 is "that name is taken". The
             * relay's refusal text was captured just above, so the message
             * says which one it is instead of collapsing all three into
             * "refused" and sending the operator to the wrong place. */
            if (st->detail[0]) {
                /* ⛔ THE RELAY'S SENTENCE IS COPIED BEFORE st_set FORMATS IT.
                 * st_set writes the formatted result into the same buffer the
                 * %s argument points at, which is a read and a write of one
                 * object with no order between them, and the sentence came out
                 * empty. The copy is what makes the message say which of the
                 * several 503 causes this is. */
                char why_copy[256];
                snprintf(why_copy, sizeof why_copy, "%s", st->detail);
                st_set(st, WS_ERR_HTTP, status, "relay refused the upgrade with "
                       "HTTP %d: %s", status, why_copy);
                free(headers);
                return -1;
            }
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

/* ⛔ AND WHEN THERE IS NO `Sec-WebSocket-Key`, THIS LEAVES THE REQUEST IN
 * `rbuf` RATHER THAN CLEARING IT, because that request is very likely a plain
 * `POST /v1/pair` and the body has to survive for the handler to read.
 *
 * A pair is an ordinary HTTP POST and not an upgrade, so it is refused here --
 * correctly, because this is the upgrade door. But refusing it is only useful
 * if the caller can then get at the body it refused, and for a long time the
 * two were wired so it could not: every `POST /v1/pair` died with "no
 * Sec-WebSocket-Key in the upgrade request", which is true and tells an
 * operator nothing.
 *
 * So the contract is: on a missing key, `rbuf` holds the whole request and the
 * caller may read the body out of it. `rbuf` is only reset once a key has been
 * found, which is what makes that true. A caller that does not care gets the
 * -1 and the same buffer it would have got anyway. */
int ws_server_peek(Transport *t, WsSession *ws, char *request_path,
                   size_t pathlen, ws_status *st) {
    return ws_server_peek_tok(t, ws, request_path, pathlen, NULL, 0, st);
}

int ws_server_peek_tok(Transport *t, WsSession *ws, char *request_path,
                       size_t pathlen, char *peek_token,
                       size_t peek_token_len, ws_status *st) {
    if (peek_token && peek_token_len) {
        peek_token[0] = 0;
    }
    memset(ws, 0, sizeof *ws);
    ws->t = t;
    ws->is_client = 0;
    ws->keepalive_ms = WS_KEEPALIVE_DEFAULT_MS;
    ws->fq_cap = WS_DEFAULT_QUEUE_BYTES;
    ws->max_frame = WS_HELLO_DEFAULT_FRAME;
    ws->max_sessions = WS_HELLO_DEFAULT_SESSIONS;
    buf_init(&ws->rbuf);
    buf_init(&ws->frag);
    buf_init(&ws->spill);

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
    char token_hdr[1024] = "";
    {
        /* case-insensitive header scan, bounded to the header block.
         *
         * ⛔ THE SCAN DOES NOT STOP AT THE KEY. It used to `break` as soon as
         * it found `Sec-WebSocket-Key`, because that was the only header it
         * wanted. Adding the token made that a live bug in the wrong
         * direction: a client that puts `X-Relay-Token` AFTER the key -- which
         * RFC 9110 explicitly allows, since header order carries no meaning --
         * was refused as "no token was sent" while presenting a perfectly good
         * one. The whole scan runs to the end of the header block and both
         * values are taken from it. */
        char *line = strstr(headers, "\r\n");
        while (line) {
            line += 2;
            if (k == NULL && strncasecmp(line, "Sec-WebSocket-Key:", 18) == 0) {
                k = line + 18;
                while (*k == ' ') {
                    k++;
                }
            }
            /* ⛔ THE RELAY TOKEN IS READ HERE, IN THE SAME SCAN, AND NOT BY A
             * SECOND PASS OVER THE HEADERS. `ws_server_peek` used to keep only
             * the WebSocket key and throw the rest away, so a relay that wanted
             * to authenticate an upgrade had no way to get the credential out
             * of the request without re-reading the raw buffer -- and the raw
             * buffer is RESET at the end of this function, so the second pass
             * was reading freed memory. One scan, one parse, both values.
             *
             * The copy is BOUNDED and the value is taken up to the next CR or
             * LF, so a header claiming to be 60 KB long cannot make this grow
             * and cannot smuggle a second header line in through the value. A
             * token with a CR or LF in it is not a token; it is a request
             * smuggling attempt, and truncating at the line break is what
             * makes that a parse rather than an execution. */
            if (token_hdr[0] == 0 &&
                strncasecmp(line, "X-Relay-Token:", 14) == 0) {
                const char *tv = line + 14;
                while (*tv == ' ') {
                    tv++;
                }
                size_t tn = 0;
                while (tv[tn] != 0 && tv[tn] != '\r' && tv[tn] != '\n' &&
                       tn < sizeof token_hdr - 1) {
                    token_hdr[tn] = tv[tn];
                    tn++;
                }
                token_hdr[tn] = 0;
            }
            char *nx = strstr(line, "\r\n");
            if (nx == NULL) {
                break;
            }
            line = nx;
        }
    }
    if (peek_token && token_hdr[0]) {
        snprintf(peek_token, peek_token_len, "%s", token_hdr);
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

    /* ⛔ THE 101 IS NOT SENT HERE. See ws.h: a relay has to be able to answer
     * 503 on the upgrade when the node is not connected, and by this point the
     * request target is known but nothing has been written. ws_server_accept
     * sends it once the caller has decided. */
    snprintf(ws->pending_accept_key, sizeof ws->pending_accept_key, "%s", key);
    free(headers);

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

/* Tell the peer why the session is ending, from inside the decoder.
 *
 * ⛔ A CLOSE FRAME WITH A REASON, SENT FROM THE DECODER, BECAUSE EVERY FAILURE
 * HERE IS ONE THE PEER CANNOT DIAGNOSE ON ITS OWN. "message too large" with no
 * frame leaves a client to guess whether it or the relay is at fault, and the
 * ajam relay's own 1009 "bad multiplex frame" is the precedent: a close that
 * names the fault is worth a close that does not. */
static void logf_close(WsSession *ws, int code, const char *reason) {
    if (ws->t != NULL && !ws->close_sent) {
        ws_close_with(ws, code, reason);
    }
}

/* ⛔ A DIAGNOSTIC, AND IT IS SILENT UNLESS THE OPERATOR ASKED FOR ONE.
 *
 * This file had no logging at all, and adding liveness needed somewhere to say
 * why a session was being failed. The obvious place -- an unconditional
 * `fprintf(stderr, ...)` -- is wrong here: a relay runs many sessions, the
 * keepalive runs every 20 s in each, and a line per failed liveness check on a
 * busy relay turns an operator's stderr into noise they learn to ignore. It
 * also competes for the same stderr that an ssh `ProxyCommand` uses to talk to
 * the operator, which is the one channel this process has.
 *
 * So the counters are the report -- `ws_control_drops()` and
 * `ws_pings_in_flight()` are read by `relay --status` and the node's log -- and
 * this is the line a developer sees when they have asked to see it. */
static void ws_note(const char *fmt, ...) {
    const char *v = getenv("DROPSSH_VERBOSE");
    if (v == NULL || (*v != '1' && *v != 'y')) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "dropssh ws: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

int ws_server_accept(WsSession *ws, ws_status *st) {
    char accept[64];
    dropssh_ws_accept(ws->pending_accept_key, accept, sizeof accept);
    char resp[256];
    int rn = snprintf(resp, sizeof resp,
                      "HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
    if (rn < 0 || (size_t)rn >= sizeof resp) {
        st_set(st, WS_ERR_CONNECT, 0, "the 101 response is too long to build");
        return -1;
    }
    if (ws->t == NULL || ws->t->write(ws->t, resp, (size_t)rn) != 0) {
        st_set(st, WS_ERR_CONNECT, 0, "could not write the 101 response");
        return -1;
    }
    ws->pending_accept_key[0] = 0;
    if (st) {
        st->err = WS_OK;
        st->detail[0] = 0;
    }
    return 0;
}

int ws_server(Transport *t, WsSession *ws, char *request_path,
              size_t pathlen, ws_status *st) {
    if (ws_server_peek(t, ws, request_path, pathlen, st) != 0) {
        return -1;
    }
    return ws_server_accept(ws, st);
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
    /* ⛔ THE WRITE PATHS GUARD ON `t` AND NOT ONLY ON `closed`, BECAUSE
     * `ws_close` NULLS `t` BUT DID NOT SET `closed`, AND `send_frame`
     * DEREFERENCES `t` UNCONDITIONALLY.
     *
     * So a write on a session that has been closed -- or one that has been
     * MOVED FROM, and a moved-from session is all-zero and has `t == NULL` and
     * `closed == 0` -- passed the `closed` check and dereferenced NULL. The
     * operator's `!open_ok` refusal path in `relay.c` is one `client_release`
     * away from a late write, and U2's whole point is that a future refusal
     * below the move must be safe. A NULL deref is a crash of the whole relay,
     * which is the failure this file has produced three times already.
     *
     * `t == NULL` is exactly the condition under which `send_frame` cannot do
     * its job, so returning -1 here is not a new policy: it is the -1 the
     * write would have had to return anyway, decided before the dereference. */
    if (ws == NULL || ws->closed || ws->t == NULL) {
        return -1;
    }
    size_t off = 0;
    /* ⛔ ONE FRAME PER WRITE, UP TO min(64 KiB, the relay's maxFrameBytes), NOT
     * ONE FRAME FOR THE WHOLE STREAM. The relay states maxFrameBytes: 65536 in
     * its hello and drops oversized frames, and a 40 MiB scp is one write at
     * the syscall level. The limit is read from the hello rather than
     * hardcoded, so a relay that advertises less gets obeyed. */
    size_t CHUNK = ws->max_frame ? ws->max_frame : WS_HELLO_DEFAULT_FRAME;
    if (CHUNK > WS_MAX_FRAME) {
        CHUNK = WS_MAX_FRAME;
    }
    if (CHUNK == 0) {
        CHUNK = WS_HELLO_DEFAULT_FRAME;
    }
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

int ws_write_text(WsSession *ws, const unsigned char *buf, size_t len) {
    /* Same guard as ws_write, for the same reason: see the note there. `t` is
     * the pointer send_frame dereferences, so a session with no transport has
     * nothing to write to. */
    if (ws == NULL || ws->closed || ws->t == NULL) {
        return -1;
    }
    return send_frame(ws, 0x1, buf, len);
}

/* A half-close: tell the peer this side is done sending, and leave the
 * session readable. Used when the ssh server has exited and its output is on
 * the wire, so the far end sees the end of the stream rather than a cut. */
void ws_shutdown_tx(WsSession *ws) {
    /* `t` guarded as well: send_frame dereferences it, and a session that has
     * been closed or moved from has none. Same reason as ws_write. */
    if (ws == NULL || ws->close_sent || ws->t == NULL) {
        return;
    }
    send_frame(ws, 0x8, NULL, 0);
    ws->close_sent = 1;
}

/* -------------------------------------------------- forward declarations --
 * The frame queue and the byte stream are defined below ws_close, which frees
 * the queue, so the two names it uses are declared first rather than the close
 * path being moved. */
static void ws_free_frames(WsSession *ws);

/* ⛔ ONE OWNER PER SESSION, AND THE MOVE IS A NAMED OPERATION BECAUSE A
 * STRUCT COPY OF A SESSION IS ALWAYS A BUG IN THIS FILE.
 *
 * A WsSession's ownership lives in its buffer POINTERS (rbuf, frag, spill) and
 * in the Transport it wraps. `memcpy` of a session copies the struct AND
 * leaves two names pointing at the same four allocations, so the first close
 * frees memory the second still points at. This file and `relay.c` have
 * produced three double frees that way, and every one of them took down a whole
 * process rather than one session.
 *
 * The two hand-written versions of the move were `dst = src; memset(&src,0)`
 * and `*dst = *src; memset(&src,0)`. Both are correct and BOTH are one edit
 * away from being a copy: delete the `memset` and the ownership is aliased
 * again, silently, with no compiler error and no test -- which is exactly the
 * state U2 describes (0/6 on the plant). So the move is one function, it takes
 * a POINTER TO THE SOURCE so it can clear the source itself, and the source
 * is left as a WsSession with no transport and no buffers. Every `ws_close` on
 * a moved-from session is then a no-op by construction rather than by a
 * convention someone has to remember.
 *
 * ⛔ AND THE INERT SOURCE IS NOT "AN UNUSABLE WsSession": it is one that is
 * safe to close and safe to close AGAIN, because the two things close() needs
 * -- a transport to shut and buffers to free -- are both gone. That is what
 * lets every existing `ws_close(&ws)` on a refusal path above the move stay
 * exactly where it is, and it is why a future refusal added BELOW the move
 * cannot reintroduce the aliasing. */
void ws_move(WsSession *dst, WsSession *src) {
    if (dst == NULL || src == NULL) {
        return;
    }
    *dst = *src;
    /* Clear the whole source, not just the buffers: leaving a stale `t` behind
     * would let a close shut a transport the new owner is already using. */
    memset(src, 0, sizeof *src);
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
    /* ⛔ CLOSING SETS `closed` AS WELL AS NULLING `t`, so that "this session
     * is finished" is ONE fact with two representations that cannot disagree.
     * Before this, `ws_close` nulled `t` and left `closed` clear, so the write
     * paths -- which test `closed` -- believed a closed session was still open
     * and dereferenced a NULL `t`. See the note in ws_write. */
    ws->closed = 1;
    ws_free_frames(ws);
    buf_free(&ws->rbuf);
    buf_free(&ws->frag);
    buf_free(&ws->spill);
}

void ws_close_with(WsSession *ws, int code, const char *reason) {
    if (ws == NULL || ws->t == NULL || ws->close_sent) {
        ws_close(ws);
        return;
    }
    /* RFC 6455 close payload: 2-byte big-endian code, then the reason, and the
     * whole control frame must be 125 bytes or fewer. */
    unsigned char pl[123];
    size_t rl = reason ? strlen(reason) : 0;
    if (rl > sizeof pl - 2) {
        rl = sizeof pl - 2;
    }
    pl[0] = (unsigned char)(code >> 8);
    pl[1] = (unsigned char)(code & 0xff);
    if (rl) {
        memcpy(pl + 2, reason, rl);
    }
    send_frame(ws, 8, pl, rl + 2);
    ws->close_sent = 1;
    ws_close(ws);
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
/* ------------------------------------------------------------------ the
 * frame queue. Every layer that needs message boundaries reads from here, and
 * ws_read, the byte-stream path, is defined on top of it. There is ONE
 * decoder in this file: the byte-stream reader used to have its own, and two
 * decoders over one buffer is how two of them came to disagree about what had
 * been consumed.
 */
static void ws_free_frames(WsSession *ws) {
    WsFrame *f = ws->fq_head;
    while (f) {
        WsFrame *n = f->next;
        free(f);
        f = n;
    }
    ws->fq_head = NULL;
    ws->fq_tail = NULL;
    ws->fq_count = 0;
    ws->fq_bytes = 0;
    /* ⛔ THE CONTROL QUEUE IS FREED WITH THE DATA QUEUE, IN `ws_close`, and
     * not by a separate call at each of the places a session ends. Two free
     * paths is how a queue gets leaked, and a leaked queue on a relay that
     * has held many sessions is memory nobody accounts for. */
    WsFrame *c = ws->cq_head;
    while (c) {
        WsFrame *n = c->next;
        free(c);
        c = n;
    }
    ws->cq_head = NULL;
    ws->cq_tail = NULL;
    ws->cq_count = 0;
}

/* ⛔ THE OUTBOUND CONTROL QUEUE, AND ITS OVERFLOW POLICY IS A DROP AND A
 * COUNT (dropssh#10 adopt 2, from wstunnel `websocket.rs:228`).
 *
 * A control frame -- a ping, a pong, a close -- must never block the data path.
 * Blocking is the deadlock this file introduced and then removed; the reader
 * would sit in a write while the far end was not reading, and the session would
 * stop with every log line correct. So the queue is bounded and, when it is
 * full, the frame is DROPPED and counted.
 *
 * Dropping a control frame is the right answer rather than a compromise: a
 * dropped pong makes one ping unanswerable, and the in-flight counter then
 * fails the session if the peer was genuinely gone. Dropping data instead
 * would corrupt a session; blocking would deadlock it. The count is what makes
 * the drop visible -- wstunnel's comment is the whole point, and ours is
 * `ws_control_drops()`, which `relay --status` and the node's own log report.
 */
static int ws_queue_control(WsSession *ws, int opcode, const unsigned char *pl,
                            size_t plen) {
    if (ws == NULL || ws->t == NULL || ws->closed) {
        return -1;
    }
    if (ws->cq_count >= WS_CONTROL_QUEUE_MAX) {
        /* ⛔ THE DROP IS COUNTED, NOT LOGGED, because a control frame is sent
         * on a timer and a log line per dropped frame is a log line per
         * keepalive interval on a congested relay. The counter is read by
         * `dropssh relay --status` as `control_dropped`. */
        ws->cq_dropped++;
        return -1;
    }
    WsFrame *f = malloc(sizeof *f + plen);
    if (f == NULL) {
        ws->cq_dropped++;
        return -1;
    }
    f->next = NULL;
    f->opcode = opcode;
    f->len = plen;
    if (plen) {
        memcpy(f->data, pl, plen);
    }
    if (ws->cq_tail) {
        ws->cq_tail->next = f;
    } else {
        ws->cq_head = f;
    }
    ws->cq_tail = f;
    ws->cq_count++;
    return 0;
}

/* Drain queued control frames onto the wire, in order, stopping at the first
 * failure so a full socket leaves the rest queued rather than reordering. */
static void ws_flush_control(WsSession *ws) {
    while (ws->cq_head) {
        WsFrame *f = ws->cq_head;
        if (send_frame(ws, f->opcode, f->data, f->len) != 0) {
            return;     /* the socket is full; the rest stay in order behind it */
        }
        ws->cq_head = f->next;
        if (ws->cq_head == NULL) {
            ws->cq_tail = NULL;
        }
        ws->cq_count--;
        free(f);
    }
}

unsigned ws_control_drops(const WsSession *ws) {
    return ws ? ws->cq_dropped : 0;
}

unsigned ws_pings_in_flight(const WsSession *ws) {
    return ws ? ws->pings_in_flight : 0;
}

void ws_set_queue_cap(WsSession *ws, size_t bytes) {
    ws->fq_cap = bytes ? bytes : WS_DEFAULT_QUEUE_BYTES;
}

int ws_set_limits(WsSession *ws, unsigned max_frame, unsigned max_sessions) {
    /* ⛔ THE RELAY'S LIMITS ARE FLOORED, NOT TAKEN VERBATIM. A hello naming
     * maxFrameBytes: 0 or maxSessions: 0 is a relay saying nothing useful,
     * and obeying it literally would mean this node refuses to open a session
     * and refuses to send a byte. The default is used instead, and a limit
     * below the default is honoured because a relay may legitimately cap
     * lower. */
    ws->max_frame = max_frame ? max_frame : WS_HELLO_DEFAULT_FRAME;
    if (ws->max_frame > WS_MAX_FRAME) {
        ws->max_frame = WS_HELLO_DEFAULT_FRAME;
    }
    ws->max_sessions = max_sessions ? max_sessions : WS_HELLO_DEFAULT_SESSIONS;
    return 0;
}

unsigned ws_max_frame(const WsSession *ws)    { return ws->max_frame; }
unsigned ws_max_sessions(const WsSession *ws) { return ws->max_sessions; }
int  ws_close_code(const WsSession *ws)       { return ws->close_code; }
const char *ws_close_reason(const WsSession *ws) { return ws->close_reason; }

/* Queue one decoded message. Returns 0, or -1 when the queue is over its byte
 * cap, in which case the session is closed rather than grown: a peer that
 * sends faster than a session drains must not be able to choose this
 * process's allocation. */
static int queue_frame(WsSession *ws, int opcode, const unsigned char *pl,
                       size_t plen) {
    if (ws->fq_bytes + plen > ws->fq_cap) {
        return -1;
    }
    WsFrame *f = malloc(sizeof *f + plen);
    if (f == NULL) {
        return -1;
    }
    f->next = NULL;
    f->opcode = opcode;
    f->len = plen;
    if (plen) {
        memcpy(f->data, pl, plen);
    }
    if (ws->fq_tail) {
        ws->fq_tail->next = f;
    } else {
        ws->fq_head = f;
    }
    ws->fq_tail = f;
    ws->fq_count++;
    ws->fq_bytes += plen;
    return 0;
}

/* Record a peer's close, decoding the 2-byte code and the reason when the
 * frame carried one. A close with no payload is a code of 1005 by
 * specification; reporting 0 (which the header does, meaning "no close
 * arrived") would be a lie the operator reads as "the peer vanished". */
static void note_close(WsSession *ws, const unsigned char *pl, size_t plen) {
    if (plen >= 2) {
        ws->close_code = (int)((pl[0] << 8) | pl[1]);
        size_t rl = plen - 2;
        if (rl >= sizeof ws->close_reason) {
            rl = sizeof ws->close_reason - 1;
        }
        /* ⛔ THE REASON IS SANITISED HERE, AT THE POINT IT ENTERS THE PROCESS,
         * NOT AT EACH PRINT SITE.
         *
         * A close reason is a network-controlled string and every consumer of
         * it writes to a terminal: `connect` prints it, `relay --status` and
         * the logs carry it, and this process is an ssh ProxyCommand whose
         * stderr is read by a person. A reason containing an ESC, a BEL or a
         * bare CR can repaint the line, ring, or overwrite what an operator
         * has already read, and the relay's own reason on r11 is derived from
         * a node's text.
         *
         * ⛔ IT WAS NOT SANITISED ANYWHERE, AND THIS WAS FOUND BY A REVIEW
         * THAT ASKED "what happens to a value that came off the wire on a path
         * I widened" rather than by a failing test. `connect` gained a
         * hand-rolled filter for the `reject` path in the same change, which
         * is exactly the one-read-path-one-write-path violation this file
         * exists to prevent: two filters, one of them missed the next caller.
         * The fix is here so there is one.
         *
         * ⛔ WHAT IS DROPPED, AND WHY IT IS NOT ESCAPED. Control characters
         * below 0x20 and DEL are removed. They are not turned into `\x1b`
         * sequences, because this string is a SENTENCE about a connection that
         * gets read by eye: an escaped `^[[2J` is noise, and the thing the
         * operator needs is "node disconnected", not the bytes a peer chose.
         * Printable ASCII, UTF-8 continuation bytes and any byte >= 0x80 are
         * kept, so a non-English reason is not mangled. */
        size_t k = 0;
        for (size_t i = 0; i < rl; i++) {
            unsigned char ch = pl[2 + i];
            if (ch < 0x20 || ch == 0x7f) {
                if (ch == ' ' || ch == '\t') {
                    /* a tab inside a sentence is spacing, not a cursor move */
                    ws->close_reason[k++] = ' ';
                }
                continue;
            }
            ws->close_reason[k++] = (char)ch;
        }
        ws->close_reason[k] = 0;
    } else {
        ws->close_code = 1005;
    }
}

/* Decode every complete message in rbuf, in arrival order. Returns 0, or -1
 * on a close (ws->closed set) or fatal framing. */
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

        /* ⛔ THE PAYLOAD IS UNMASKED IN PLACE AND THEN CONSUMED IMMEDIATELY.
         * An earlier version returned a pointer into rbuf without consuming
         * it, so the same frame was returned forever and the peer was flooded
         * until it gave up. Every branch below either queues the bytes or
         * drops them, and the consume at the bottom of the loop is the only
         * place rbuf advances, so a frame has exactly one fate. */
        if (opcode == 0x8) {          /* close */
            buf_consume(&ws->rbuf, idx + plen);
            note_close(ws, pl, plen);
            ws->closed = 1;
            return -1;
        }
        if (opcode == 0x9) {          /* ping -> pong, same payload */
            /* ⛔ THE PONG IS SENT BEFORE THE PING IS CONSUMED, AND A FAILED
             * PONG DOES NOT CLOSE THE SESSION. RFC 6455 lets a peer send an
             * unsolicited ping and answers it, and the answer is best effort
             * by design: a pong that cannot be written is a symptom, and the
             * in-flight counter below is what actually decides liveness. */
            send_frame(ws, 0xA, pl, plen);
            buf_consume(&ws->rbuf, idx + plen);
            continue;
        }
        if (opcode == 0xA) {          /* pong */
            /* ⛔ ANY PONG RESETS THE IN-FLIGHT COUNT, WHEREVER IT CAME FROM,
             * AND THAT IS THE WHOLE OF THE LIVENESS RULE (dropssh#10 adopt 1).
             *
             * Before this the keepalive sent a ping every 20 s and tracked
             * nothing: a half-dead socket -- a peer that has gone away without
             * the TCP connection noticing -- stayed open indefinitely and
             * reported silence, which is the exact failure every project in
             * that sweep reported (chisel #608, ligolo #101, sshx #49,
             * websocat #35). Ours was ours too; nothing counted.
             *
             * wstunnel counts pings in flight and fails the session at three
             * unanswered ones, and any pong resets the count whether it
             * answers a ping we sent or arrives unsolicited. The NUMBER is
             * the adoptable part: a mechanism without a threshold is a
             * mechanism that never gives up, which is what we had. */
            if (ws->pings_in_flight > 0) {
                ws->pings_in_flight--;
            }
            buf_consume(&ws->rbuf, idx + plen);
            continue;
        }
        if (opcode == 0x0) {          /* continuation */
            if (!ws->frag_open) {
                *fatal = 1;
                ws->closed = 1;
                return -1;
            }
            /* ⛔ THE ASSEMBLY IS CAPPED, AND EACH CONTINUATION IS CHECKED
             * BEFORE IT IS APPENDED. Every individual frame is already bounded
             * by WS_MAX_FRAME above, but a peer can send any number of
             * continuations and the ASSEMBLY is what grows -- so without this
             * check a peer picks the size of the allocation this process
             * makes on its behalf, one legal 16 MiB frame at a time. The
             * limit is the same 16 MiB, which is above any message the relay
             * protocol produces (maxFrameBytes is 65536) and below anything
             * that would matter.
             *
             * The check is on the total BEFORE the append, so the buffer never
             * reaches the limit rather than reaching it and then failing. */
            if (ws->frag.len + plen > WS_MAX_FRAME) {
                logf_close(ws, 1009, "message too large");
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
                /* ⛔ THE COMPLETED FRAGMENT ASSEMBLY KEEPS THE OPCODE OF THE
                 * FIRST FRAGMENT, not of the last. A text control message
                 * split across two continuations must be reported as text; a
                 * decoder that takes the continuation's opcode (0) or the last
                 * frame's reports something the multiplexed path would then
                 * mis-dispatch. This is the same defect as "the opcode
                 * reported is the last one for both frames", caught at the
                 * fragmentation boundary. */
                int rc = queue_frame(ws, ws->frag_opcode, ws->frag.p,
                                     ws->frag.len);
                buf_reset(&ws->frag);
                ws->frag_open = 0;
                if (rc != 0) {
                    *fatal = 1;
                    ws->closed = 1;
                    return -1;
                }
            }
            continue;
        }
        /* 0x1 text, 0x2 binary. A non-final data frame opens a fragment
         * sequence whose opcode is remembered; a final one is queued whole. */
        if (!fin) {
            /* Same cap as the continuation path: the opening frame of a
             * fragmented message is part of the same assembly. */
            if (plen > WS_MAX_FRAME) {
                logf_close(ws, 1009, "message too large");
                *fatal = 1;
                ws->closed = 1;
                return -1;
            }
            buf_reset(&ws->frag);
            if (buf_append(&ws->frag, pl, plen) != 0) {
                *fatal = 1;
                ws->closed = 1;
                return -1;
            }
            ws->frag_open = 1;
            ws->frag_opcode = opcode;
            buf_consume(&ws->rbuf, idx + plen);
            continue;
        }
        if (queue_frame(ws, opcode, pl, plen) != 0) {
            /* over the queue cap: refuse rather than grow, and say why. */
            *fatal = 1;
            ws->closed = 1;
            return -1;
        }
        buf_consume(&ws->rbuf, idx + plen);
    }
}

/* One turn of the keepalive clock, shared by both read paths.
 *
 * ⛔ LIVENESS IS A POLICY NUMBER AND NOT A TIMER (dropssh#10 adopt 1, from
 * wstunnel `websocket.rs:104`).
 *
 * The rule: a ping is sent when nothing else has been, and every ping that
 * goes out without a pong coming back counts. At `WS_MAX_PINGS_IN_FLIGHT`
 * unanswered pings the session is failed. The number is three because that is
 * what wstunnel uses and because three keepalive intervals is long enough to
 * survive a busy network and short enough that a dead peer is noticed while an
 * operator is still watching.
 *
 * ⛔ AND THE COUNT IS A COUNT, NOT A TIMESTAMP, BECAUSE A TIMESTAMP ANSWERS A
 * DIFFERENT QUESTION. "Nothing has arrived in 60 s" is wrong on a healthy idle
 * ssh session, which is quiet for minutes by design; "three pings I sent have
 * not been answered" is true on a dead peer and false on a live one whatever
 * the traffic is. The first version of this tracked only the last transmit
 * time, and a session with no traffic at all looked exactly like a dead one.
 */
static void maybe_keepalive(WsSession *ws) {
    if (ws->keepalive_ms == 0) {
        return;
    }
    if (ws->pings_in_flight >= WS_MAX_PINGS_IN_FLIGHT) {
        /* ⛔ THREE UNANSWERED PINGS IS A FAILED SESSION, AND THE REASON SAYS
         * WHICH COUNT TRIPPED, because "connection closed" on an ssh
         * ProxyCommand is the same sentence for a relay that is down, a node
         * that has gone, and a network that has gone quiet. */
        ws_note("closing: %u pings sent and none answered", ws->pings_in_flight);
        ws->closed = 1;
        return;
    }
    unsigned now = now_ms();
    if (now - ws->last_tx_ms >= ws->keepalive_ms) {
        /* ⛔ THE PING GOES ON THE CONTROL QUEUE, NOT STRAIGHT ON THE WIRE, so a
         * congested socket cannot make the keepalive block the data path -- the
         * deadlock `d986214` removed. If the queue is full the ping is dropped
         * and counted, and the in-flight counter above is what notices a peer
         * that has genuinely gone. */
        if (ws_queue_control(ws, 0x9, NULL, 0) == 0) {
            ws->pings_in_flight++;
        }
        /* ⛔ `last_tx_ms` IS NOT ADVANCED HERE, AND THAT IS DELIBERATE. It
         * records the last time BYTES WENT OUT, and a ping is not traffic: an
         * ssh session that is genuinely idle must still be pinged, or the
         * counter below never moves and the liveness check never runs. */
    }
    ws_flush_control(ws);
}

/* Deliver the head of the frame queue, copying the payload so it outlives the
 * queue node. The copy is what lets a caller hold a control message across the
 * next ws_recv_frame call without the pointer dying with the node.
 *
 * ⛔ WHY THE COPY IS NOT AN OPTIMISATION BUT A CORRECTNESS REQUIREMENT. The
 * queue node is freed on delivery, so handing back a pointer into it would be
 * the "return a pointer without consuming" defect with a different spelling:
 * the bytes are alive but owned by freed memory. Callers queue the bytes
 * somewhere else anyway, and a 64 KiB frame is one memcpy against a socket
 * read that already copied it once. */
static int deliver(WsSession *ws, int *opcode, buffer *dst, size_t *len,
                   int *closed, int *fatal) {
    WsFrame *f = ws->fq_head;
    ws->fq_head = f->next;
    if (!ws->fq_head) {
        ws->fq_tail = NULL;
    }
    if (ws->fq_count) {
        ws->fq_count--;
    }
    ws->fq_bytes -= f->len;
    *opcode = f->opcode;
    *len = f->len;
    *closed = 0;
    int rc = 0;
    if (f->len) {
        rc = buf_append(dst, f->data, f->len);
    }
    free(f);
    if (rc != 0) {
        ws->closed = 1;
        *closed = 1;
        if (fatal) {
            *fatal = 1;
        }
        return -1;
    }
    return 1;
}

int ws_recv_frame(WsSession *ws, int *opcode, buffer *dst, size_t *len,
                  int *closed, int *fatal) {
    *closed = 0;
    if (fatal) {
        *fatal = 0;
    }
    buf_reset(dst);
    for (;;) {
        if (ws->fq_head) {
            return deliver(ws, opcode, dst, len, closed, fatal);
        }
        if (ws->closed) {
            *closed = 1;
            return -1;
        }
        int f = 0;
        if (decode_available(ws, &f) != 0) {
            *closed = 1;
            if (fatal) {
                *fatal = f;
            }
            return -1;
        }
        if (ws->fq_head) {
            continue;
        }
        int eof = 0;
        if (read_more(ws, &eof) != 0) {
            ws->closed = 1;
            *closed = 1;
            if (fatal) {
                *fatal = 1;
            }
            return -1;
        }
        if (eof) {
            ws->closed = 1;
            *closed = 1;
            return -1;
        }
        /* ⛔ SILENCE IS NOT AN ERROR AND IS NOT A CLOSE. The relay sends a
         * keepalive every 25 s and an ssh session can go quiet for minutes
         * while someone reads. Reporting either as "connection lost" kills a
         * working session, so the loop yields and retries, and the keepalive
         * below is what stops an intermediate cutting a quiet one. */
        maybe_keepalive(ws);
        dropssh_sleep_ms(20);
    }
}

int ws_poll_frame(WsSession *ws, int *opcode, buffer *dst, size_t *len,
                  int *closed, int *fatal) {
    *closed = 0;
    if (fatal) {
        *fatal = 0;
    }
    buf_reset(dst);
    /* ⛔ THE KEEPALIVE RUNS HERE AND NOT ONLY IN ws_recv_frame, BECAUSE THE
     * OPERATOR'S LOOP IS THIS ONE.
     *
     * `ws_recv_frame` is the blocking reader and the node's thread uses it. The
     * operator is a single-threaded event loop over stdin and the socket, and
     * it calls `ws_poll_frame` precisely because it must not block. So with the
     * keepalive only in `ws_recv_frame`, the operator never pinged, never
     * counted, and never failed a liveness check -- which is the half of the
     * connection where a half-dead peer is most likely, because the operator is
     * the one waiting on a reply.
     *
     * This is the same "the path that waits is not the path that runs" shape as
     * the stdin-starvation bug, and it was found by asking which of the two
     * readers the operator actually uses rather than by reading either. */
    maybe_keepalive(ws);
    if (ws->fq_head) {
        return deliver(ws, opcode, dst, len, closed, fatal);
    }
    if (ws->closed) {
        *closed = 1;
        return -1;
    }
    int f = 0;
    if (decode_available(ws, &f) != 0) {
        *closed = 1;
        if (fatal) {
            *fatal = f;
        }
        return -1;
    }
    if (ws->fq_head) {
        return deliver(ws, opcode, dst, len, closed, fatal);
    }
    /* ⛔ THE TRANSPORT IS POLLED, NOT BLOCKING-READ. A non-blocking read that
     * returns 0 bytes and no EOF means "nothing right now", and the caller
     * comes back. The first version read the transport only when the decode
     * buffer ALREADY held bytes, so on a fresh connection nothing was ever
     * fetched: the relay's 514-byte banner sat in the socket, ws_poll_frame
     * returned 0 forever, and the operator read nothing at all while every
     * log line said the pair was up.
     *
     * The read is safe against blocking because the transport's read already
     * returns 0 with eof=0 rather than waiting -- that is the contract
     * transport.h states and ws_recv_frame's loop relies on. So this reads
     * whatever has arrived and returns immediately either way. */
    {
        int eof = 0;
        if (read_more(ws, &eof) != 0) {
            ws->closed = 1;
            *closed = 1;
            if (fatal) {
                *fatal = 1;
            }
            return -1;
        }
        if (decode_available(ws, &f) != 0) {
            *closed = 1;
            if (fatal) {
                *fatal = f;
            }
            return -1;
        }
        if (ws->fq_head) {
            return deliver(ws, opcode, dst, len, closed, fatal);
        }
    }
    return 0;
}

int ws_read(WsSession *ws, unsigned char *buf, size_t len, int *closed) {
    *closed = 0;
    if (len == 0) {
        return 0;
    }
    /* ⛔ THE BYTE STREAM IS DEFINED ON TOP OF THE FRAME QUEUE, NOT BESIDE IT.
     * A second decoder over the same buffer is how the two came to disagree
     * about what had been consumed. This one takes whole frames, copies out
     * what the caller asked for, and keeps the REST in the session so a
     * 64 KiB frame read through a 32 KiB buffer arrives whole rather than
     * being split at whatever size the caller happened to pass. */
    while (ws->spill.len == 0) {
        int op = 0, cl = 0, f = 0;
        size_t n = 0;
        int r = ws_recv_frame(ws, &op, &ws->spill, &n, &cl, &f);
        if (r < 0) {
            *closed = 1;
            return f ? -1 : 0;
        }
        if (n == 0 && !cl) {
            continue;
        }
    }
    size_t take = ws->spill.len < len ? ws->spill.len : len;
    memcpy(buf, ws->spill.p, take);
    buf_consume(&ws->spill, take);
    return (int)take;
}
