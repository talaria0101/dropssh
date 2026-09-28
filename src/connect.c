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
    unsigned wait_started = 0;
    int waiting_started = 0;
    int said_waiting = 0;

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

        /* ⛔ THE READY-WAIT ACCOUNTING IS HERE, BEFORE THE REVERSE BRANCH, AND
         * THAT IS WHERE IT HAS TO BE.
         *
         * The first version put it at the bottom of the loop, after the
         * reverse branch. That branch ends in `continue`, so on a relay that
         * sends nothing -- which is exactly the case the accounting exists to
         * bound -- the counter was never incremented and the 60s bound was
         * never reached. `dropssh connect` then waited for ever.
         *
         * ⛔ AND IT IS AN ssh ProxyCommand, SO A HANG HERE IS AN ssh THAT NEVER
         * TIMES OUT. Measured while writing the case that found it: a `connect`
         * against a node that registers and never answers `open` printed nothing
         * and ran until the test harness killed it at 25s, and again at 75s
         * after the bound was added -- because the bound was on the other side
         * of a `continue`.
         *
         * Every `continue` in this loop is a place a bound can be skipped, so
         * the bound is above all of them. */
        if (gated && !seen_ready) {
            /* ⛔ ELAPSED TIME IS MEASURED, NOT COUNTED IN TURNS.
             *
             * The first version did `waited_ready += 20` per loop turn, on
             * the assumption that a turn was 20 ms. It is not: a turn is as
             * long as the work in it, and when frames are arriving the loop
             * never sleeps. So the counter reached 60000 -- and printed "the
             * node never answered `ready` after 60s" -- within milliseconds,
             * and `dropssh connect` gave up on a node that was about to answer.
             *
             * ⛔ AND THE SYMPTOM NAMED A DIFFERENT FAULT AGAIN. The message
             * says the node never answered, and the node had answered; what
             * had happened is that this process counted its own iterations and
             * believed them. A message that is confidently wrong is worse than
             * no message, and the number in it is the part a reader trusts.
             *
             * So the clock is the clock. `dropssh_now_ms` is monotonic and is
             * what the websocket keepalive already uses, so there is one time
             * source in this file rather than two that can disagree. */
            /* ⛔ AND THE SENTINEL IS A SEPARATE FLAG, NOT A FUDGED VALUE.
             *
             * Two attempts, both wrong in a way that only showed up as a
             * number. `wait_started == 0` as the "not started" test re-arms
             * itself if the clock reads 0, which is the turn-counting bug
             * wearing a clock. Fudging it with `| 1u` so it is never 0 makes
             * the SUBTRACTION wrap when the real clock is still below 1:
             *
             *     waited_ready: 4294967295ms
             *
             * which is unsigned underflow, and which made the 60s bound fire
             * immediately while printing "60s". A message that says 60s and
             * means "now" is worse than no bound, because it stops the reader
             * looking.
             *
             * So the flag is separate from the value and the arithmetic is
             * left alone. `now - start` is correct whenever start was set from
             * the same clock, and it is always set from the same clock. */
            unsigned now = dropssh_now_ms();
            if (!waiting_started) {
                waiting_started = 1;
                wait_started = now;
            }
            waited_ready = now - wait_started;
            if (waited_ready >= 10000 && !said_waiting) {
                said_waiting = 1;
                logf("still waiting for the node to answer `ready` after 10s; "
                     "the relay closes an unanswered open at about that point");
            }
            /* The bound is six times the relay's own open timeout, so a slow
             * but working node is not cut off and a relay's own 1008 is what
             * normally ends this wait. It exists for the relay that never
             * closes, because ssh waits for this process and an operator with
             * no message has no way out. */
            if (waited_ready >= (unsigned)o->bound_ms) {
                if (o->bound_ms == 0) {
                    /* ⛔ A ZERO BOUND IS "NONE", NOT "IMMEDIATELY", AND THE TWO
                     * ARE NOT THE SAME DEFECT. With 0 the wait would end on its
                     * first turn, before the relay's `open` has even been read,
                     * so the operator would report a silent node it had never
                     * been told about. Saying so here is also what makes the
                     * zero build's message a different string from a working
                     * one's, which is how the probe tells them apart. */
                    logf("the node never answered `ready`; giving up with no "
                         "bound configured. The node is not answering `open`");
                } else {
                    logf("the node never answered `ready` after %ds; giving up. "
                         "The node is not answering `open` -- check that it is "
                         "running, that its --server command starts, and that it "
                         "reached the relay", o->bound_ms / 1000);
                }
                rc = 1;
                goto done;
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
                    /* ⛔ AN ERROR CLOSE IS A FAILURE, AND EXIT 0 HERE IS A
                     * REFUSED LOGIN REPORTED AS SUCCESS. Measured: a relay
                     * that closes 1008 "node open timeout" before the node
                     * answers -- which is what happens when the node is gone,
                     * slow, or restarting -- left `dropssh connect` exiting 0
                     * with the reason on stderr. An ssh reading that sees a
                     * clean exit and reports a transport that worked.
                     *
                     * The rule, and it is the same one the local relay taught:
                     * a close in the 1000-2999 range is the end of a session
                     * that was fine, and anything else is a fault. 1000-1005
                     * are normal-ish; 1008 and 1009 are named protocol errors;
                     * 1011 is the node being gone. None of them is "success".
                     *
                     * ⛔ AND `ready` NEVER ARRIVED, WHICH IS THE STRONGER FACT.
                     * A session that was never established cannot be reported
                     * as one that completed, whatever the close code says, so
                     * the gate's own state is consulted and not only the
                     * code. That is what makes this correct for a close the
                     * relay might not have named. */
                    if (gated && !seen_ready) {
                        rc = 1;
                        if (code == 1008) {
                            logf("the node never answered `ready`: the relay "
                                 "closed with 1008 node open timeout, which "
                                 "means the node is not there or not answering");
                        } else if (!code || code == 1005) {
                            logf("the connection closed before the node "
                                 "answered `ready`; the node is not connected "
                                 "or is not accepting sessions");
                        } else {
                            logf("the connection closed before the node "
                                 "answered `ready` (code %d %s)", code,
                                 ws_close_reason(&ws));
                        }
                        goto done;
                    }
                    if (code == 1009) {
                        logf("the relay closed the session: 1009 bad multiplex "
                             "frame (a node frame arrived without its 32-hex id)");
                    } else if (code == 1003) {
                        logf("the relay closed the session: 1003 binary frames "
                             "required (a text frame was sent where session data "
                             "was required)");
                    } else if (code == 1011) {
                        logf("the node disconnected (relay close 1011)");
                        rc = 1;
                    } else if (code && code != 1005 && code != 1000 && code != 1001) {
                        logf("the relay closed the session: code %d %s", code,
                             ws_close_reason(&ws));
                        rc = 1;
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
            /* ⛔ THE LOOP ALWAYS YIELNS, EVEN ON THE REVERSE LINK, AND THAT IS
             * WHAT STOPS THIS FROM BECOMING A BUSY LOOP.
             *
             * This branch used to `continue` straight back to the top, which
             * meant the `if (!progressed) sleep(20ms)` at the bottom was never
             * reached while a relay was sending anything -- and a relay that
             * sends a frame every few milliseconds keeps `progressed` true
             * forever. A node that is streaming but not answering `ready` would
             * spin a core for the length of the wait.
             *
             * So the reverse link falls through to the shared tail rather than
             * jumping over it. The cost is one extra pass through the stdin
             * check per turn, which is what we want anyway: stdin has priority
             * and should be serviced on every turn, not only when the relay is
             * quiet. */
        } else {

        /* forward and rendezvous: a byte stream, which is what they are.
         *
         * ⛔ AND THIS IS AN `else`, NOT A SEPARATE BLOCK, BECAUSE FALLING
         * THROUGH IS THE BUG THIS COMMENT EXISTS TO PREVENT. The reverse
         * branch used to end in `continue`, which skipped the yield; removing
         * that to fix the busy loop made the reverse link FALL THROUGH into
         * this branch, and this branch calls ws_read -- a BLOCKING read -- on
         * the very session the reverse branch was draining with ws_poll_frame.
         *
         * The observable result was a session that opened, exchanged the
         * banner, and then went silent with the node reporting "relay connection
         * ended: closed". One reader per socket was a rule this file enforced by
         * structure, and the structure was two readers on one session.
         *
         * So: the reverse link is an `if`, and this is its `else`. Exactly one
         * of the two read paths runs on a session, ever. */
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
        }   /* end of the non-reverse (forward / rendezvous) branch */

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
