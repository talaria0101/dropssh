/* connect.c - the operator side: one byte pipe, in and out of this process.
 *
 * ⛔ THIS IS WHAT ssh's ProxyCommand RUNS, SO IT SPEAKS SSH ON ITS OWN STDIN
 * AND STDOUT AND NOTHING ELSE. It prints no banner, no log line to stdout, and
 * no progress. A single stray byte on stdout is not a cosmetic problem here: it
 * lands in the middle of an ssh version string and the handshake fails with an
 * error that names a protocol problem rather than the log line that caused it.
 * Every diagnostic therefore goes to stderr, and that is enforced by the fact
 * that the only stdout write in this file is the relay write itself.
 *
 * ⛔ ONE EVENT LOOP, NO FORK, NO THREAD. The previous version forked a child to
 * pump stdin while the parent read the relay, and `fork()` copies the mbedTLS
 * context rather than just the descriptors, so a child writing while the parent
 * read corrupted the record layer. The symptom was exact and looked like a
 * network fault: "could not write to the relay" from the child, on a
 * connection and a network that were both fine. A thread is not the fix
 * either, because a thread shares the context LEGITIMATELY and mbedTLS's read
 * and write are not concurrent-safe on one context. So this is a single loop
 * with poll() over stdin and a non-blocking relay read, and one context, used
 * by one thread.
 */
#include "dropssh.h"
#include "transport.h"
#include "ws.h"
#include "tls.h"
#include "util.h"
#include "relayproto.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void logf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "dropssh: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    fflush(stderr);
}

/* How the operator's end of the relay is speaking, decided by the path rather
 * than by a flag. ⛔ THIS IS DECIDED BY COUNTING PATH SEGMENTS, NOT BY A MODE
 * FLAG, because a flag is something an operator can set wrong. The relay's own
 * rule, from docs/reverse-relay.md:
 *
 *   /v1/connect/<name>       the multiplexed REVERSE path: a text `ready` may
 *                            arrive, and a data frame is BARE (the relay
 *                            prepends the id for the node)
 *   /connect/<host>/<port>   a FORWARD: raw bytes, no id, no control messages
 *   /connect/<name>          a rendezvous (dropssh relay): raw bytes
 */
typedef enum {
    LINK_FORWARD = 0,   /* /connect/<host>/<port> */
    LINK_REVERSE,       /* /v1/connect/<name>, or /v1/node/<name> */
    LINK_RENDEZVOUS     /* /connect/<name> */
} link_kind;

static link_kind classify(const char *path) {
    if (strncmp(path, "/v1/", 4) == 0) {
        return LINK_REVERSE;
    }
    /* /connect/<a>/<b> is a forward (host + port); /connect/<a> is a name. */
    const char *rest = path;
    if (strncmp(rest, "/connect/", 9) == 0) {
        rest += 9;
    } else if (strncmp(rest, "/node/", 6) == 0) {
        return LINK_RENDEZVOUS;
    }
    int slashes = 0;
    for (const char *p = rest; *p; p++) {
        if (*p == '/') {
            slashes++;
        }
    }
    return slashes >= 1 ? LINK_FORWARD : LINK_RENDEZVOUS;
}

int dropssh_connect(dropssh_opts *o) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stderr, NULL, _IONBF, 0);

    char token[1024];
    const char *tok = o->token;
    if ((tok == NULL || tok[0] == 0) && o->generate) {
        char base[512];
        snprintf(base, sizeof base, "https://%s", o->relay);
        ws_status st;
        memset(&st, 0, sizeof st);
        if (dropssh_mint_token(base, NULL, token, sizeof token, &st) != 0) {
            logf("could not mint a relay token: %s", ws_strerror(&st));
            return 4;
        }
        tok = token;
        /* ⛔ THE TOKEN IS NOT ECHOED, NOT LOGGED, AND NOT WRITTEN ANYWHERE.
         * It is a credential the relay issued for this session, and the only
         * thing that needs it is the header below. A `set -x` or a log tail
         * that captured it would compromise it for as long as it lives. */
    }

    char err[512] = "";
    int local = strncmp(o->relay, "unix://", 7) == 0;
    Transport *t;
    if (local) {
        t = transport_tcp_unix(o->relay + 7, err, sizeof err);
        if (t == NULL) {
            logf("%s", err);
            return 4;
        }
    } else {
        t = transport_tcp(o->relay, o->port, dropssh_proxy_host(),
                          dropssh_proxy_port(), o->connect_ms, err, sizeof err);
        if (t == NULL) {
            logf("cannot reach the relay %s:%d: %s", o->relay, o->port, err);
            logf("if this is a name-resolution failure, the cage has no resolver: "
                 "set DROPSSH_PROXY to a proxy that resolves, or use --proxy");
            return 4;
        }
        t = transport_tls(t, o->relay, o->insecure, err, sizeof err);
        if (t == NULL) {
            logf("TLS to the relay failed: %s", err);
            const char *le = dropssh_tls_lasterror();
            if (le) {
                logf("%s", le);
            }
            return 4;
        }
    }

    char path[512];
    if (o->path && o->path[0]) {
        snprintf(path, sizeof path, "%s", o->path);
    } else if (o->name && o->name[0]) {
        snprintf(path, sizeof path, "/v1/connect/%s", o->name);
    } else {
        snprintf(path, sizeof path, "%s", DROPSSH_DEFAULT_FORWARD);
    }
    link_kind kind = classify(path);

    char host_header[300];
    if (local) {
        snprintf(host_header, sizeof host_header, "localhost");
    } else {
        snprintf(host_header, sizeof host_header, "%s:%d", o->relay, o->port);
    }
    WsSession ws;
    ws_status st;
    memset(&st, 0, sizeof st);
    if (ws_client(t, host_header, path, tok, "dropssh", &ws, &st) != 0) {
        logf("%s", ws_strerror(&st));
        t->close(t);
        return 4;
    }
    if (o->verbose) {
        logf("paired on %s%s (%s)", o->relay, path,
             kind == LINK_REVERSE ? "reverse, multiplexed" :
             kind == LINK_FORWARD ? "forward" : "rendezvous");
    }

    /* ⛔ STDIN IS PUT IN ITS OWN QUEUE AND THE SOCKET'S READS ARE SERVED FROM
     * ONE LOOP, so a session that is half-duplex (the operator's ssh sends
     * "exec", then waits for output) still moves bytes. The previous design
     * read stdin to EOF before reading the socket, or forked, and the fork
     * corrupted the TLS context. poll() over both, one context, one thread. */
    int rc = 0;
    int stdin_open = 1;
    /* The reverse link is gated on the node's `ready`; the other two are not.
     * The flag is a named constant rather than an expression repeated at each
     * use, because "which links gate" is the whole decision. */
    const int gated = (kind == LINK_REVERSE);
    int seen_ready = !gated;
    unsigned char inbuf[32768];
    /* One frame buffer for the whole loop, reused per frame. The reverse link
     * is the only one that reads frames; the forward link reads the byte
     * stream into `buf` below. */
    buffer framebuf;
    buf_init(&framebuf);
    unsigned waited_ready = 0;

    /* ⛔ ONE LOOP, NON-BLOCKING READS ON BOTH LEGS, AND STDIN HAS PRIORITY.
     * The blocking version of this loop read stdin under poll() and then fell
     * into ws_recv_frame, which waits for a frame for as long as it takes. A
     * multiplexed operator has to service BOTH: ssh writes a 3.6 KB KEX
     * stream and then waits for the reply, and the node's reply arrives only
     * after the whole stream has gone. The blocking read won the race and the
     * operator read 2000 bytes of 3658 and then sat waiting for a frame that
     * could not arrive because the rest of the stream was still in a pipe.
     *
     * Measured, not assumed: replaying a recorded 3658-byte client stream
     * through the relay delivered exactly 2000 bytes, and every log line
     * said the writes succeeded. The fix is structural. Both legs are
     * non-blocking, the loop never blocks, and stdin is serviced FIRST on
     * every turn so the far end always has the bytes it needs to reply. */
    for (;;) {
        int progressed = 0;

        /* 1. stdin -> the relay, as BARE binary frames. FIRST, every turn --
         *    but only once the node has said `ready` on the reverse link.
         *
         * ⛔ THE OPERATOR WAITS FOR `ready` BEFORE IT SENDS A BYTE, AND THE
         * REASON IS A RACE MEASURED AGAINST tcp.ssh.relay.ajam.dev.
         *
         * The relay does not create the session until the node answers `open`
         * with `ready`. An operator that writes its ssh banner immediately --
         * before that answer has been forwarded -- has its bytes relayed to a
         * node socket where the id does not exist yet, and BOTH ends are
         * closed:
         *
         *   operator  <- close 1008 "wait for ready"
         *   node      <- close 1003 "unknown session id"
         *
         * So the bytes are not queued, not delayed and not dropped: the relay
         * tears the session down, and the operator sees a close whose reason
         * names a handshake it never saw. Holding stdin until `ready` is the
         * only correct behaviour, and it costs one round trip that the ssh
         * banner exchange was going to pay anyway.
         *
         * The forward and rendezvous links have no `ready` and are not gated:
         * seen_ready starts true for them, so the gate is a no-op there rather
         * than a special case in the send path. */
        if (stdin_open && (!gated || seen_ready)) {
            struct pollfd ps = { .fd = 0, .events = POLLIN };
            int pr = poll(&ps, 1, 0);
            if (pr > 0 && (ps.revents & (POLLIN | POLLHUP | POLLERR))) {
                ssize_t n = read(0, inbuf, sizeof inbuf);
                if (n > 0) {
                                        /* ⛔ BARE, ALWAYS, ON EVERY LINK. The reverse relay
                     * PREPENDS the 32-hex id on the operator's leg and the
                     * forward path has no id at all, so an operator that
                     * prefixes one has it doubled on the reverse path
                     * (measured: 68 bytes arrive instead of 38) and hands 32
                     * hex characters of its own to the ssh server on the
                     * forward one. That was B3. */
                    if (ws_write(&ws, inbuf, (size_t)n) != 0) {
                        logf("could not write to the relay");
                        rc = 1;
                        break;
                    }
                    progressed = 1;
                } else if (n == 0) {
                    /* ⛔ EOF ON STDIN IS "NO MORE INPUT", NOT "SESSION OVER",
                     * AND IT DOES NOT CLOSE THE RELAY LINK. This is what a
                     * ProxyCommand sees: ssh writes its conversation and then
                     * closes stdin, but the REPLY is still coming. An earlier
                     * version sent a websocket Close here, which the relay
                     * read as "tear every attached operator down", so the
                     * node's echo arrived into a dead socket and the operator
                     * exited having read nothing: a close 1005 and no output.
                     *
                     * So stdin EOF only stops reading stdin. This link stays
                     * open and the loop keeps reading the relay until the
                     * RELAY closes, which is the only event that genuinely
                     * ends a session. */
                    stdin_open = 0;
                } else if (errno != EINTR && errno != EAGAIN) {
                    stdin_open = 0;
                }
            }
        }

        /* 2. the relay -> stdout, draining every frame that is ready. */
        if (kind == LINK_REVERSE) {
            for (;;) {
                int op = 0, closed = 0, fatal = 0;
                size_t n = 0;
                int r = ws_poll_frame(&ws, &op, &framebuf, &n, &closed, &fatal);
                if (r < 0) {
                    int code = ws_close_code(&ws);
                    if (code == 1009) {
                        logf("the relay closed the session: 1009 bad multiplex "
                             "frame (a node frame arrived without its 32-hex id)");
                    } else if (code == 1003) {
                        logf("the relay closed the session: 1003 binary frames "
                             "required (a text frame was sent where session data "
                             "was required)");
                    } else if (code == 1011) {
                        logf("the node disconnected (relay close 1011)");
                    } else if (code && code != 1005) {
                        logf("the relay closed the session: code %d %s", code,
                             ws_close_reason(&ws));
                    } else if (fatal) {
                        logf("the relay sent framing this client cannot read");
                        rc = 1;
                    } else {
                        const char *le = dropssh_tls_lasterror();
                        logf("relay read failed: %s", le ? le : "the socket closed");
                        rc = 1;
                    }
                    goto done;
                }
                if (r == 0) {
                    break;
                }
                progressed = 1;
                if (op == 0x1) {      /* control: the node's `ready` */
                    char *json = malloc(n + 1);
                    if (json == NULL) {
                        continue;
                    }
                    memcpy(json, framebuf.p, n);
                    json[n] = 0;
                    char verb[64] = "";
                    relay_parse_control(json, verb, sizeof verb, NULL, 0);
                    if (strcmp(verb, "ready") == 0) {
                        if (o->verbose) {
                            logf("node is ready");
                        }
                        seen_ready = 1;
                    } else if (strcmp(verb, "close") == 0) {
                        if (o->verbose) {
                            logf("the node closed the session");
                        }
                        free(json);
                        goto done;
                    } else if (o->verbose) {
                        logf("relay control: %.100s", json);
                    }
                    free(json);
                    continue;
                }
                if (n == 0) {
                    continue;
                }                /* ⛔ NO ID IS STRIPPED HERE, because on the operator's leg the
                 * relay has already stripped it. An operator that removed 32
                 * bytes would eat the first 32 bytes of every ssh packet. */
                size_t off = 0;
                int out_closed = 0;
                while (off < n) {
                    ssize_t w = write(1, framebuf.p + off, n - off);
                    if (w > 0) {
                        off += (size_t)w;
                        continue;
                    }
                    if (w < 0 && errno == EINTR) {
                        continue;
                    }
                    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        struct pollfd pw = { .fd = 1, .events = POLLOUT };
                        poll(&pw, 1, 5000);
                        continue;
                    }
                    out_closed = 1;   /* the operator's ssh hung up */
                    break;
                }
                if (out_closed) {
                    rc = 0;
                    goto done;
                }
            }
            continue;   /* stdin first, again, on the next turn */
        }

        /* forward and rendezvous: a byte stream, which is what they are. */
        for (;;) {
            unsigned char buf[32768];
            int closed = 0;
            int n = ws_read(&ws, buf, sizeof buf, &closed);
            if (n < 0) {
                const char *le = dropssh_tls_lasterror();
                logf("relay read failed: %s", le ? le : "malformed framing");
                rc = 1;
                goto done;
            }
            if (n == 0) {
                if (closed) {
                    goto done;
                }
                break;
            }
            progressed = 1;
            size_t off = 0;
            int out_closed = 0;
            while (off < (size_t)n) {
                ssize_t w = write(1, buf + off, (size_t)n - off);
                if (w > 0) {
                    off += (size_t)w;
                    continue;
                }
                if (w < 0 && errno == EINTR) {
                    continue;
                }
                if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    struct pollfd pw = { .fd = 1, .events = POLLOUT };
                    poll(&pw, 1, 5000);
                    continue;
                }
                out_closed = 1;
                break;
            }
            if (out_closed) {
                rc = 0;
                goto done;
            }
        }

                /* ⛔ IF THE OPERATOR IS STILL WAITING FOR `ready` AFTER THE RELAY'S OWN
         * OPEN TIMEOUT, SAY SO, BECAUSE THE CLOSE THAT FOLLOWS NAMES A
         * DIFFERENT THING. The relay closes an unanswered `open` with "node
         * open timeout" after about ten seconds (measured). Without this the
         * operator sits silent and then reports that close, which names the
         * NODE's silence rather than its own wait. */
        if (gated && !seen_ready) {
            waited_ready += 20;
            if (waited_ready == 10000) {
                logf("still waiting for the node to answer `ready` after 10s; "
                     "the relay closes an unanswered open at about that point");
            }
        }

        /* ⛔ A QUIET RELAY IS A 20 ms SLEEP, NOT A BUSY LOOP AND NOT A BLOCK.
         * An ssh session can be silent for minutes while somebody reads, and
         * the relay's keepalive arrives every 25 s. A busy loop would burn a
         * core for the length of a reading session; a blocking read is the
         * starvation above. */
        if (!progressed) {
            dropssh_sleep_ms(20);
        }
    }
done:
    /* ⛔ A NORMAL END IS EXIT 0 AND A BROKEN ONE IS NOT, READ FROM WHAT
     * HAPPENED RATHER THAN FROM ssh's exit status. An ssh that was refused a
     * key exits non-zero for its own reasons and this process must not turn
     * that into a transport error, while a relay that dropped the socket is a
     * transport error. */
    ws_close(&ws);
    buf_free(&framebuf);
    (void)seen_ready;
    return rc;
}
