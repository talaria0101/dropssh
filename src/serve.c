/* serve.c - the node side: a cage that has no inbound, dialling out.
 *
 * THE SHAPE, AND WHY IT IS THIS SHAPE. A cage has no port anyone can reach,
 * so it cannot be dialled. What it can do is dial OUT, so the node keeps a
 * websocket to the relay open and waits. When an operator asks for a session
 * the relay pairs them, and this process hands the paired byte stream to a
 * real ssh server on one end of a socketpair.
 *
 * ⛔ THE SSH SERVER IS A SEPARATE PROGRAM, AND IT IS NOT SSH IMPLEMENTED HERE.
 * dropbear is run with `-i`, which is its inetd mode: it reads and writes ssh
 * on descriptors 0 and 1 and never binds anything. That means dropssh does
 * not have to be correct about userauth, keys, channels, rekeying or any of
 * the rest of ssh, and every one of those keeps being maintained by the
 * project that has maintained it for twenty years. What dropssh owns is the
 * rendezvous, the framing, and the token.
 *
 * ⛔ AND `dropbear -i` IS PROBED, NOT ASSUMED. A server that exits inside the
 * probe window is a failure and its first line of output is the diagnosis; a
 * server still running is a pass. The alternative, taking the command on
 * faith, produces a relay that pairs every session with a process that dies
 * on the first byte, and the symptom is an ssh client that hangs rather than
 * an error.
 */
#include "dropssh.h"
#include "transport.h"
#include "ws.h"
#include "tls.h"
#include "util.h"
#include "relayproto.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
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

/* ------------------------------------------------------------------ probing */
/* Run `cmd` on a socketpair and report whether it stayed up. The window is
 * short on purpose: a server that cannot start says so immediately, and a
 * server that can start is blocked reading its descriptor, which is the
 * property a cage needs. */
static int probe_server(const char *cmd, char *why, size_t whylen) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        snprintf(why, whylen, "cannot create a socketpair: %s", strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        snprintf(why, whylen, "cannot fork: %s", strerror(errno));
        close(sv[0]); close(sv[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(sv[1], 0);
        dup2(sv[1], 1);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, 2);
        }
        close(sv[0]); close(sv[1]);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(sv[1]);

    const unsigned WINDOW = 700;
    unsigned waited = 0;
    int alive = 1;
    unsigned char sink[256];
    while (waited < WINDOW) {
        int st = 0;
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) {
            alive = 0;
            if (WIFEXITED(st) && WEXITSTATUS(st) == 127) {
                snprintf(why, whylen, "the server command could not be started: %s", cmd);
            } else if (WIFEXITED(st)) {
                snprintf(why, whylen, "the server exited immediately with status %d: %s",
                         WEXITSTATUS(st), cmd);
            } else {
                snprintf(why, whylen, "the server was killed by signal %d: %s",
                         WTERMSIG(st), cmd);
            }
            close(sv[0]);
            return -1;
        }
        /* Read whatever it says and throw it away, so a chatty server cannot
         * block in write() and then be reported as wedged. */
        struct pollfd pf = { .fd = sv[0], .events = POLLIN };
        if (poll(&pf, 1, 0) > 0) {
            ssize_t n = read(sv[0], sink, sizeof sink);
            if (n <= 0) {
                break;
            }
        }
        dropssh_sleep_ms(25);
        waited += 25;
    }
    kill(pid, SIGKILL);
    int st = 0;
    waitpid(pid, &st, 0);
    close(sv[0]);
    if (alive) {
        snprintf(why, whylen, "started");
        return 0;
    }
    return -1;
}

/* -------------------------------------------------------------- the session */
/* Pump bytes both ways between the relay websocket and a socketpair whose
 * other end is the ssh server. Two directions, two poll sets, and a bounded
 * wait, because neither side is allowed to block the other out of making
 * progress. */
/* ⛔ THE TWO DIRECTIONS ARE TWO THREADS, AND THE REASON IS A DEADLOCK THIS
 * FUNCTION HAD.
 *
 * The first version was one loop that polled the server socket, then called
 * ws_read on the relay socket. ws_read does not return until it has payload
 * bytes, because an idle ssh session must not look like a closed one, so the
 * moment the client stopped sending, the call blocked inside ws_read and the
 * server-to-relay direction was never serviced again.
 *
 * The symptom was exact and read like a transport fault: the client sent
 * "exec", the server authenticated it, ran it, and wrote its output, and
 * none of it moved. Both legs were proven good in isolation first -- the
 * relay carried bytes both ways under a standalone test, and `dropbear -i`
 * on a socketpair carried a whole session under another -- so the fault had
 * to be in the thing that joined them, and it was.
 *
 * A poll loop cannot fix this, because one of its two sources has no
 * pollable descriptor: the relay's readiness is decided inside the TLS and
 * framing layers, not by a file descriptor. Two threads is the shape that
 * matches the two independent byte streams.
 */
typedef struct {
    WsSession *ws;
    int        sock;
    int        *server_done;
} pump_arg;

static void *pump_sock_to_ws(void *arg) {
    pump_arg *a = arg;
    for (;;) {
        struct pollfd pf = { .fd = a->sock, .events = POLLIN };
        int r = poll(&pf, 1, 200);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            if (a->ws->closed) {
                break;
            }
            continue;
        }
        if (pf.revents & (POLLIN | POLLHUP | POLLERR)) {
            unsigned char buf[32768];
            ssize_t n = read(a->sock, buf, sizeof buf);
            if (n > 0) {
                if (ws_write(a->ws, buf, (size_t)n) != 0) {
                    break;
                }
                continue;
            }
            if (n == 0) {
                /* ⛔ THE SERVER HANGING UP HALF-CLOSES THE RELAY RATHER THAN
                 * CLOSING IT. The exec'd command has already written its
                 * output and the exit status is on its way; closing the
                 * websocket here would race that write and lose it, which is
                 * how a command that ran to completion reported nothing. The
                 * session ends when the peer closes or the relay does. */
                ws_shutdown_tx(a->ws);
                *a->server_done = 1;
                break;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                break;
            }
        }
    }
    return NULL;
}

static void *pump_ws_to_sock(void *arg) {
    pump_arg *a = arg;
    for (;;) {
        unsigned char buf[32768];
        int closed = 0;
        int n = ws_read(a->ws, buf, sizeof buf, &closed);
        if (n < 0) {
            const char *le = dropssh_tls_lasterror();
            logf("relay read failed: %s", le ? le : "malformed framing");
            break;
        }
        if (n == 0) {
            if (closed) {
                break;
            }
            continue;
        }
        size_t off = 0;
        while (off < (size_t)n) {
            ssize_t w = write(a->sock, buf + off, (size_t)n - off);
            if (w > 0) {
                off += (size_t)w;
                continue;
            }
            if (w < 0 && errno == EINTR) {
                continue;
            }
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                struct pollfd pw = { .fd = a->sock, .events = POLLOUT };
                poll(&pw, 1, 5000);
                continue;
            }
            return NULL;
        }
    }
    return NULL;
}

static int pump_session(WsSession *ws, int sock, int *server_done) {
    pump_arg a = { .ws = ws, .sock = sock, .server_done = server_done };
    pthread_t up, down;
    if (pthread_create(&up, NULL, pump_sock_to_ws, &a) != 0) {
        return -1;
    }
    if (pthread_create(&down, NULL, pump_ws_to_sock, &a) != 0) {
        pthread_join(up, NULL);
        return -1;
    }
    pthread_join(up, NULL);
    pthread_join(down, NULL);
    return 0;
}

/* One operator session: accept the paired websocket, start the ssh server on
 * a socketpair, and pump until either side ends. */
static const char *server_passwd = NULL;
static const char *server_preload = NULL;

static int do_session(WsSession *ws, const char *servercmd,
                      const unsigned char *initial, size_t initiallen) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        logf("socketpair: %s", strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        logf("fork: %s", strerror(errno));
        close(sv[0]); close(sv[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(sv[1], 0);
        dup2(sv[1], 1);
        close(sv[0]);
        close(sv[1]);
        /* ⛔ THE SERVER'S CAGE ENVIRONMENT IS SET EXPLICITLY, NOT INHERITED BY
         * ACCIDENT. Two facts make this necessary rather than tidy:
         *
         *   - A cage has no /etc/passwd, so `dropbear -i` looks up root and
         *     finds nothing, and logs "Login attempt for nonexistent user" for
         *     a user that is there. The passwd shim fixes that, and the shim
         *     reads its database from $SANDHOME_PASSWD, so the server has to be
         *     told which file.
         *   - A statically linked server cannot be reached by LD_PRELOAD at
         *     all, so the shim is only usable against a dynamic one. That is
         *     the builder's job, and --preload is how the operator points the
         *     server at the shim the builder produced.
         *
         * Both are set on the child only. Setting them process-wide would put
         * a shim in front of dropssh's own TLS, which is a different program
         * with a different set of symbols, for no reason.
         */
        if (server_passwd && server_passwd[0]) {
            setenv("SANDHOME_PASSWD", server_passwd, 1);
        }
        if (server_preload && server_preload[0]) {
            setenv("LD_PRELOAD", server_preload, 1);
        }
        signal(SIGPIPE, SIG_DFL);
        execl("/bin/sh", "sh", "-c", servercmd, (char *)NULL);
        _exit(127);
    }
    close(sv[1]);
    int fl = fcntl(sv[0], F_GETFL, 0);
    if (fl >= 0) {
        fcntl(sv[0], F_SETFL, fl | O_NONBLOCK);
    }
    /* ⛔ THE BYTES ALREADY READ ARE THE SERVER'S FIRST INPUT AND ARE WRITTEN
     * BEFORE THE PUMP STARTS. The node's read loop had to read far enough to
     * notice that a session had begun, and that read consumed the start of
     * the ssh version string. Dropping it makes dropbear see an empty stream
     * and log "Exit before auth", which names an authentication problem and
     * is a framing one. This is the same class of bug as a lost marker prefix
     * in a line protocol, and it is invisible until the very first exchange. */
    if (initial && initiallen) {
        size_t off = 0;
        while (off < initiallen) {
            ssize_t w = write(sv[0], initial + off, initiallen - off);
            if (w <= 0) {
                if (errno == EINTR) {
                    continue;
                }
                struct pollfd pw = { .fd = sv[0], .events = POLLOUT };
                poll(&pw, 1, 5000);
                continue;
            }
            off += (size_t)w;
        }
    }
    logf("session open; ssh server: %s", servercmd);
    int server_done = 0;
    pump_session(ws, sv[0], &server_done);
    close(sv[0]);
    int st = 0;
    if (server_done) {
        waitpid(pid, &st, 0);
    } else {
        kill(pid, SIGTERM);
        dropssh_sleep_ms(100);
        if (waitpid(pid, &st, WNOHANG) != pid) {
            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
        }
    }
    logf("session closed");
    return 0;
}

/* ---------------------------------------------------------------- the node */
int dropssh_serve(dropssh_opts *o) {
    signal(SIGPIPE, SIG_IGN);
    server_passwd = o->passwd;
    server_preload = o->preload;

    char servercmd[1024];
    if (o->server && o->server[0]) {
        snprintf(servercmd, sizeof servercmd, "%s", o->server);
    } else {
        /* A dropbear with no arguments, so the defaults apply: inetd mode,
         * no fork, and whatever host key it finds or makes. */
        snprintf(servercmd, sizeof servercmd, "dropbear -i -E -F");
    }

    /* ⛔ THE SERVER IS PROBED ONCE, BEFORE THE RELAY IS DIALED, AND A FAILURE
     * STOPS THE PROCESS. Dialling first and probing later means a node that
     * registers successfully and then fails every session, which looks like a
     * relay problem and is not one. */
    char why[512];
    if (probe_server(servercmd, why, sizeof why) != 0) {
        logf("the ssh server does not run here: %s", why);
        logf("pass --server with a command that does, or --server-cmd");
        return 3;
    }
    logf("ssh server ok: %s", servercmd);

    unsigned backoff = 1;
    int sessions = 0;
    for (;;) {
        ws_status st;
        memset(&st, 0, sizeof st);
        Transport *t = NULL;
        char err[512] = "";

        int local = strncmp(o->relay, "unix://", 7) == 0;
        if (local) {
            t = transport_tcp_unix(o->relay + 7, err, sizeof err);
        } else {
            t = transport_tcp(o->relay, o->port, dropssh_proxy_host(),
                              dropssh_proxy_port(), o->connect_ms, err, sizeof err);
        }
        if (t == NULL) {
            logf("cannot reach the relay %s: %s", o->relay, err);
            goto wait_and_retry;
        }
        if (!local) {
            t = transport_tls(t, o->relay, o->insecure, err, sizeof err);
            if (t == NULL) {
                logf("TLS to the relay failed: %s", err);
                goto wait_and_retry;
            }
        }

        char path[512];
        if (o->path && o->path[0]) {
            snprintf(path, sizeof path, "%s", o->path);
        } else if (o->name && o->name[0]) {
            snprintf(path, sizeof path, "/v1/node/%s", o->name);
        } else {
            logf("a reverse node needs --name, or an explicit --path");
            t->close(t);
            return 2;
        }

        char host_header[300];
        if (local) {
            snprintf(host_header, sizeof host_header, "localhost");
        } else {
            snprintf(host_header, sizeof host_header, "%s:%d", o->relay, o->port);
        }
        WsSession ws;
        if (ws_client(t, host_header, path, o->token, "dropssh", &ws, &st) != 0) {
            logf("relay refused the node: %s", ws_strerror(&st));
            t->close(t);
            goto wait_and_retry;
        }
        logf("registered with %s as %s (path %s)", o->relay,
             o->name ? o->name : "(forward)", path);
        backoff = 1;

        /* The relay's control messages, and the sessions it opens. */
        for (;;) {
            unsigned char msg[512];
            int closed = 0;
            int r = ws_read(&ws, msg, sizeof msg, &closed);
            if (r < 0 || (r == 0 && closed)) {
                const char *le = dropssh_tls_lasterror();
                logf("relay connection ended: %s", le ? le : "closed");
                break;
            }
            if (r == 0) {
                continue;
            }
            /* A control message is a JSON object the relay sends before any
             * session bytes. A session's first bytes are the ssh version
             * string, which starts with "SSH-", so the two are told apart by
             * their first byte rather than by a heuristic on content. */
            if (msg[0] == '{') {
                char sid[80] = "";
                char verb[64] = "";
                relay_parse_control((const char *)msg, verb, sizeof verb,
                                    sid, sizeof sid);
                if (strcmp(verb, "open") == 0) {
                    logf("operator opened session %s", sid);
                } else if (strcmp(verb, "close") == 0) {
                    logf("operator closed session %s", sid);
                } else {
                    logf("relay said: %.*s", 120, (const char *)msg);
                }
                continue;
            }
            /* Not a control message: the session has begun. The bytes in
             * hand are the start of it, and they are the server's first
             * input, so they are handed over rather than discarded. */
            do_session(&ws, servercmd, msg, (size_t)r);
            sessions++;
            if (o->once) {
                ws_close(&ws);
                logf("session count %d; exiting because --once was given", sessions);
                return 0;
            }
            break;   /* the session consumed the socket; redial */
        }
        ws_close(&ws);
        if (o->once) {
            return 0;
        }
wait_and_retry:
        if (o->once) {
            return 1;
        }
        logf("retrying in %us", backoff);
        dropssh_sleep_ms(backoff * 1000);
        if (backoff < 30) {
            backoff *= 2;
        }
    }
}
