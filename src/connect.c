/* connect.c - the operator side: one byte pipe, in and out of this process.
 *
 * ⛔ THIS IS WHAT ssh's ProxyCommand RUNS, SO IT SPEAKS SSH ON ITS OWN STDIN
 * AND STDOUT AND NOTHING ELSE. It prints no banner, no log line to stdout, and
 * no progress. A single stray byte on stdout is not a cosmetic problem here: it
 * lands in the middle of an ssh version string and the handshake fails with an
 * error that names a protocol problem rather than the log line that caused it.
 * Every diagnostic therefore goes to stderr, and that is enforced by the fact
 * that the only stdout write in this file is the relay write itself.
 */
#include "dropssh.h"
#include "transport.h"
#include "ws.h"
#include "tls.h"
#include "util.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
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

/* Read the operator's ssh bytes from stdin and put them in a relay frame. The
 * two directions run as threads so neither waits on the other: ssh's first
 * write is its version string and the relay's first frame may not have
 * arrived yet, and a loop that read stdin to end before reading the socket
 * would hang on a session that is working. */
static int pump_to_relay(WsSession *ws) {
    unsigned char buf[32768];
    for (;;) {
        struct pollfd pf = { .fd = 0, .events = POLLIN };
        int r = poll(&pf, 1, 200);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r > 0 && (pf.revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(0, buf, sizeof buf);
            if (n == 0) {
                /* EOF on the operator's side: the ssh session is over. */
                return 0;
            }
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                }
                return -1;
            }
            if (ws_write(ws, buf, (size_t)n) != 0) {
                logf("could not write to the relay");
                return -1;
            }
        }
    }
}

int dropssh_connect(dropssh_opts *o) {
    signal(SIGPIPE, SIG_IGN);

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
        logf("paired on %s%s", o->relay, path);
    }

    /* the two directions */
    pid_t child = fork();
    if (child < 0) {
        logf("fork: %s", strerror(errno));
        ws_close(&ws);
        return 1;
    }
    if (child == 0) {
        /* child: stdin -> relay */
        pump_to_relay(&ws);
        _exit(0);
    }

    /* parent: relay -> stdout, and nothing else may write stdout */
    int rc = 0;
    for (;;) {
        unsigned char buf[32768];
        int closed = 0;
        int r = ws_read(&ws, buf, sizeof buf, &closed);
        if (r < 0) {
            const char *le = dropssh_tls_lasterror();
            logf("relay read failed: %s", le ? le : "malformed framing");
            rc = 1;
            break;
        }
        if (r == 0) {
            if (closed) {
                break;
            }
            continue;
        }
        size_t off = 0;
        while (off < (size_t)r) {
            ssize_t w = write(1, buf + off, (size_t)r - off);
            if (w <= 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct pollfd pw = { .fd = 1, .events = POLLOUT };
                    poll(&pw, 1, 5000);
                    continue;
                }
                /* the operator's ssh hung up */
                rc = 0;
                goto done;
            }
            off += (size_t)w;
        }
    }
done:
    ws_close(&ws);
    kill(child, SIGTERM);
    int st2 = 0;
    waitpid(child, &st2, 0);
    return rc;
}
