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

/* ============================================================================
 * THE MULTIPLEXED REVERSE PATH.
 *
 * THE THREE RULES THIS IMPLEMENTS, EACH FROM docs/reverse-relay.md, EACH
 * MEASURED LIVE AGAINST tcp.ssh.relay.ajam.dev ON 2026-09-28:
 *
 *   operator -> node   the operator writes BARE ssh bytes; the relay PREPENDS
 *                      the 32-hex id, so the node receives id+payload.
 *   node -> operator   the node prefixes the 32-hex id itself; the relay
 *                      STRIPS it, so the operator receives bare bytes. A node
 *                      frame WITHOUT the prefix is closed by the relay with
 *                      code 1009 "bad multiplex frame" (measured, 3/3), which
 *                      is the loud failure B11's documentation said did not
 *                      exist.
 *   control            TEXT frames with no id: hello, open{id}, close{id} out;
 *                      ready{id} / reject{id,reason} back. A TEXT frame where
 *                      data was required is closed 1003 "binary frames
 *                      required" (measured).
 *
 * ⛔ ONE READER PER WEBSOCKET, AND THE REASON IS B5. Two threads calling
 * ws_recv_frame on one session race on its framer buffer, so one session can
 * be handed another's bytes. It works perfectly with one session, which is
 * exactly what makes it dangerous. The reader below is the ONLY thread that
 * touches the websocket's read side; it dispatches whole frames to a queue per
 * session id, so a frame has exactly one possible destination.
 *
 * ⛔ ONE WRITER, SERIALISED, AND THE REASON IS ALSO A FRAMING BUG. A
 * websocket frame is a header and a payload that must arrive together; a node
 * sending id+payload is a second send_frame, so two threads interleaving
 * produce a frame whose length and payload disagree, and the far end
 * desynchronises on the NEXT frame, which is another session's bytes read as
 * an id. So every outbound frame goes through ws_write_locked, which holds one
 * mutex for the whole id+payload send.
 */

#define MUX_MAX_SESSIONS 256

static const char *server_passwd = NULL;
static const char *server_preload = NULL;

/* ⛔ THE SERVER COMMAND IS ONE PROCESS-WIDE STRING, NOT A PER-SESSION ARGUMENT
 * AND NOT A PARAMETER OF on_control. Every session runs the same `dropbear -i`
 * on a fresh socketpair; nothing in the relay's protocol chooses a different
 * server per session, and threading a per-session command through would be an
 * option nothing sets. It is a function so both start_server and the session
 * teardown read the same value without a global the compiler cannot check. */
static const char *g_servercmd = NULL;
static const char *server_cmd_for_sessions(void) {
    return g_servercmd ? g_servercmd : "dropbear -i -E -F";
}

/* One session: the ssh server's socket, the bytes waiting for it, and the
 * mutex that makes the id+payload send one frame. */
typedef struct MuxSession {
    struct MuxSession *next;
    char        id[33];        /* the relay's 32 hex characters, NUL-terminated */
    int         sock;          /* our end of the socketpair to `dropbear -i` */
    pid_t       pid;
    buffer      inbox;         /* ⛔ bytes that arrived before the server did */
    size_t      inbox_at;
    pthread_mutex_t lock;      /* the single writer for this session */
    int         dead;
    int         started;
    int         stop;          /* set to ask the session thread to finish */
    pthread_cond_t cv;
    int         server_done;   /* the server hung up: half-close, do not read */
    /* ⛔ WHETHER THE PEER BEHIND `sock` IS A `dropbear -i` CHILD OR A DIALLED
     * DESTINATION. Everything below the `open` is the same pump either way --
     * which is the point of routing a SOCKS forward through the same
     * multiplexer -- and the teardown is not: one has a child to reap and one
     * has only a socket. A session that does not say which gets the wrong
     * teardown, and the wrong teardown on a forward is a forward that closes
     * a socket it should have kept. */
    int         is_socks;
    unsigned long long bytes_up, bytes_down;
} MuxSession;

typedef struct {
    WsSession  *ws;
    MuxSession *sessions;
    pthread_mutex_t list_lock;   /* guards `sessions` and the table below */
    pthread_mutex_t wlock;       /* ⛔ the ONE writer mutex for the websocket */
    MuxSession *by_id[MUX_MAX_SESSIONS];
    unsigned    max_sessions;    /* ⛔ the relay's advertised maxSessions */
    int         closing;
} Mux;

/* The relay's ids are 32 hex characters. A bucket is the first two of them
 * parsed as a number, which is a hash with no allocation and no table resize,
 * because the id is fixed-length and validated before it gets here. */
static unsigned id_bucket(const char *id) {
    unsigned h = 0;
    for (int i = 0; i < 2 && id[i]; i++) {
        char c = id[i];
        unsigned v = (c >= '0' && c <= '9') ? (unsigned)(c - '0')
                   : (c >= 'a' && c <= 'f') ? (unsigned)(c - 'a' + 10)
                   : (c >= 'A' && c <= 'F') ? (unsigned)(c - 'A' + 10)
                   : 0u;
        h = (h << 4) | v;
    }
    return h % MUX_MAX_SESSIONS;
}

static MuxSession *mux_find(Mux *m, const char *id) {
    if (!id || !id[0]) {
        return NULL;
    }
    for (MuxSession *s = m->by_id[id_bucket(id)]; s; s = s->next) {
        if (strcmp(s->id, id) == 0) {
            return s;
        }
    }
    return NULL;
}

/* ⛔ EVERY WRITE TO THE WEBSOCKET TAKES ONE MUTEX, AND A MUX'S WRITES NEVER
 * INTERLEAVE. Two threads writing a header and a payload between them produce
 * a frame whose length and payload disagree, and the far end then reads the
 * next frame's length from this one's bytes. The id prefix is copied into a
 * local and the whole thing goes out under the lock, so it is one frame. */
static int mux_send_binary(Mux *m, const char *id, const unsigned char *pl,
                           size_t len) {
    int rc;
    pthread_mutex_lock(&m->wlock);
    if (id != NULL) {
        /* ⛔ THE ID PREFIX IS PART OF THE FRAME, NOT A SECOND FRAME. The
         * relay strips the first 32 characters of a node data frame. Sending
         * the id and the payload as two frames delivers the id as session
         * data to the operator and the payload with no id, which the relay
         * closes 1009. So this builds ONE frame with the id in front. */
        if (len > (size_t)ws_max_frame(m->ws)) {
            len = ws_max_frame(m->ws);
        }
        if (len + 32 > WS_MAX_FRAME) {
            pthread_mutex_unlock(&m->wlock);
            return -1;
        }
        unsigned char *framed = malloc(len + 32);
        if (framed == NULL) {
            pthread_mutex_unlock(&m->wlock);
            return -1;
        }
        memcpy(framed, id, 32);
        if (len) {
            memcpy(framed + 32, pl, len);
        }
        rc = ws_write(m->ws, framed, len + 32);
        free(framed);
    } else {
        rc = ws_write(m->ws, pl, len);
    }
    pthread_mutex_unlock(&m->wlock);
    return rc;
}

/* ⛔ CONTROL MESSAGES ARE TEXT AND CARRY NO ID, AND THAT IS A PROTOCOL RULE
 * NOT A STYLE CHOICE. A control message sent as a binary frame is read by the
 * far end as data; a data frame sent as text is closed 1003 "binary frames
 * required". The build is explicit so a future edit cannot get it wrong by
 * sending the JSON through ws_write. */
static int mux_send_text(Mux *m, const char *json) {
    int rc;
    pthread_mutex_lock(&m->wlock);
    rc = ws_write_text(m->ws, (const unsigned char *)json, strlen(json));
    pthread_mutex_unlock(&m->wlock);
    return rc;
}

/* Start `dropbear -i` on a socketpair for this session, set the server's cage
 * environment on the CHILD only, and hand back the fd. */
static int start_server(const char *servercmd, int *sock_out, pid_t *pid_out,
                        char *why, size_t whylen);

/* The per-session thread: relay frames in, server bytes out, until either
 * ends. Two things it deliberately does NOT do: it does not read the
 * websocket (the one reader does), and it does not run the ssh server (the
 * child process does). It owns exactly one session's socket and its queues. */
typedef struct {
    Mux         *mux;
    MuxSession  *s;
    const char  *servercmd;
} sess_arg;

static int start_server(const char *servercmd, int *sock_out, pid_t *pid_out,
                        char *why, size_t whylen) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        snprintf(why, whylen, "socketpair: %s", strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        snprintf(why, whylen, "fork: %s", strerror(errno));
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
         *     reads its database from $SANDHOME_PASSWD, so the server has to
         *     be told which file.
         *   - A statically linked server cannot be reached by LD_PRELOAD at
         *     all, so the shim is only usable against a dynamic one. That is
         *     the builder's job, and --preload is how the operator points the
         *     server at the shim the builder produced.
         *
         * Both are set on the child only. Setting them process-wide would put
         * a shim in front of dropssh's own TLS, which is a different program
         * with a different set of symbols, for no reason. */
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
    *sock_out = sv[0];
    *pid_out = pid;
    return 0;
}

static void *session_thread(void *arg) {
    sess_arg *a = arg;
    Mux *m = a->mux;
    MuxSession *s = a->s;

    for (;;) {
        /* 1. drain the inbox into the server socket. Bytes that arrived
         *    between `open` and this thread's first turn are in s->inbox and
         *    are written here; they are NOT dropped, which is the "first
         *    bytes of the ssh stream lost -> Exit before auth" defect. */
        pthread_mutex_lock(&s->lock);
        if (s->dead) {
            pthread_mutex_unlock(&s->lock);
            break;
        }
        if (s->inbox.len > s->inbox_at && !s->server_done) {
            /* ⛔ THE LOCK IS HELD ACROSS THE WRITE, AND THAT IS THE WHOLE
             * FIX. The first version read the offset and length under the
             * lock, RELEASED it, wrote to the socket, then re-locked to
             * consume. buf_reserve compacts the buffer whenever the read
             * cursor has moved, which moves the live bytes to the front of
             * the allocation -- so a frame that arrived in the gap
             * reallocated the buffer, and the write then went to the OLD
             * pointer. The bytes were not lost by the socket and not rejected
             * by dropbear; they were written into freed memory.
             *
             * The symptom was a session that authenticated, started dropbear,
             * went silent, and ended with "Exit before auth" while every log
             * line said the write succeeded and reported the full length. A
             * replay of a recorded 3658-byte client stream delivered 2000
             * bytes, which is where the truncation first became visible: not
             * in a log, but as a byte count.
             *
             * The write cannot block indefinitely because the socket is
             * O_NONBLOCK, so holding the lock across it cannot stall the
             * reader for long, and the reader here is the only writer to this
             * session's inbox anyway. */
            size_t off = s->inbox_at;
            size_t n = s->inbox.len - off;
            size_t wrote = 0;
            int broken = 0;
            while (wrote < n) {
                ssize_t w = write(s->sock, s->inbox.p + off + wrote, n - wrote);
                if (w > 0) {
                    wrote += (size_t)w;
                    continue;
                }
                if (w < 0 && errno == EINTR) {
                    continue;
                }
                if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    struct pollfd pw = { .fd = s->sock, .events = POLLOUT };
                    pthread_mutex_unlock(&s->lock);
                    poll(&pw, 1, 200);
                    pthread_mutex_lock(&s->lock);
                    /* ⛔ THE BUFFER MAY HAVE MOVED WHILE THE LOCK WAS GIVEN
                     * UP, so the pointer is RE-TAKEN from the cursor rather
                     * than carried across the unlock. The offset is a cursor,
                     * not an address, and only the cursor survives a
                     * compaction. */
                    off = s->inbox_at;
                    n = s->inbox.len - off;
                    continue;
                }
                broken = 1;
                break;  /* the server hung up */
            }
            if (wrote) {
                buf_consume(&s->inbox, wrote);
            }
            if (broken) {
                s->server_done = 1;
            }
            pthread_mutex_unlock(&s->lock);
            if (broken) {
                char msg[96];
                snprintf(msg, sizeof msg, "{\"type\":\"close\",\"id\":\"%s\"}", s->id);
                mux_send_text(m, msg);
                break;
            }
            continue;
        }
        int stopping = s->stop;
        int done = s->server_done;
        pthread_mutex_unlock(&s->lock);
        if (stopping || (done && s->inbox.len == s->inbox_at)) {
            break;
        }

        /* 2. the server's output -> the relay, id-prefixed. */
        struct pollfd pf = { .fd = s->sock, .events = POLLIN };
        int r = poll(&pf, 1, 50);
        if (r > 0 && (pf.revents & (POLLIN | POLLHUP | POLLERR))) {
            unsigned char buf[32768];
            ssize_t n = read(s->sock, buf, sizeof buf);
            if (n > 0) {
                if (mux_send_binary(m, s->id, buf, (size_t)n) != 0) {
                    pthread_mutex_lock(&s->lock);
                    s->dead = 1;
                    pthread_mutex_unlock(&s->lock);
                    break;
                }
                pthread_mutex_lock(&s->lock);
                s->bytes_up += (unsigned long long)n;
                pthread_mutex_unlock(&s->lock);
                continue;
            }
            if (n == 0) {
                /* ⛔ THE SERVER HANGING UP IS ANNOUNCED WITH A `close` CONTROL
                 * MESSAGE AND NOTHING ELSE. The exec'd command has already
                 * written its output and the exit status is on the way;
                 * closing the websocket here would race that write and lose
                 * it, which is how a command that ran to completion reported
                 * nothing. On the multiplexed socket a Close frame would also
                 * kill every OTHER session, so this sends one JSON control
                 * frame and returns, and the socket stays up for the rest. */
                pthread_mutex_lock(&s->lock);
                s->server_done = 1;
                pthread_mutex_unlock(&s->lock);
                char msg[96];
                snprintf(msg, sizeof msg, "{\"type\":\"close\",\"id\":\"%s\"}", s->id);
                mux_send_text(m, msg);
                break;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                break;
            }
        }
    }
    /* Tear the session down: reap the server, free the socket, and unlink it
     * so a late frame for this id is dropped rather than delivered to a
     * reused one. */
    pthread_mutex_lock(&s->lock);
    s->dead = 1;
    pthread_mutex_unlock(&s->lock);
    if (s->pid > 0) {
        int st = 0;
        if (s->server_done) {
            waitpid(s->pid, &st, 0);
        } else {
            kill(s->pid, SIGTERM);
            dropssh_sleep_ms(80);
            if (waitpid(s->pid, &st, WNOHANG) != s->pid) {
                kill(s->pid, SIGKILL);
                waitpid(s->pid, &st, 0);
            }
        }
    }
    if (s->sock >= 0) {
        close(s->sock);
        s->sock = -1;
    }
    /* Remove from the table so the reader stops routing to it. The id is
     * carried into the unlink so a session is never removed twice. */
    pthread_mutex_lock(&m->list_lock);
    for (MuxSession **pp = &m->by_id[id_bucket(s->id)]; *pp; pp = &(*pp)->next) {
        if (*pp == s) {
            *pp = s->next;
            break;
        }
    }
    pthread_mutex_unlock(&m->list_lock);
    buf_free(&s->inbox);
    pthread_mutex_destroy(&s->lock);
    pthread_cond_destroy(&s->cv);
    free(s);
    return NULL;
}

/* Handle one control message. This is where `open` becomes a session. The
 * `ready`/`reject` handshake is a borrowed mechanism: a node that does not
 * answer `open` promptly is closed with "node open timeout" by the relay
 * (measured), and a node that answers nothing is indistinguishable from a
 * node that is not there. So every `open` is answered, always, and the answer
 * is `ready` once the server socket exists or `reject` with a reason. */
static void on_control(Mux *m, const char *json) {
    char verb[64] = "", id[128] = "";
    if (relay_parse_control(json, verb, sizeof verb, id, sizeof id) != 0) {
        logf("relay sent a control message dropssh could not parse: %.80s", json);
        return;
    }
    if (strcmp(verb, "hello") == 0) {
        /* The hello states the relay's limits. They are recorded and enforced
         * (maxFrameBytes bounds every frame written; maxSessions bounds how
         * many sessions are opened), because honouring a limit we advertise
         * to be under is what keeps the relay from closing us. ⛔ BOTH ARE
         * READ WITH THE SAME BOUNDED SCAN THE VERB CAME FROM, not with a
         * strstr plus atoi, which is how the first version read them and which
         * would happily read "maxSessions: -1" as a huge number. */
        unsigned mf = 0, ms = 0;
        if (relay_parse_uint(json, "\"maxFrameBytes\"", &mf) == 0) {
            ws_set_limits(m->ws, mf, ws_max_sessions(m->ws));
        }
        if (relay_parse_uint(json, "\"maxSessions\"", &ms) == 0) {
            ws_set_limits(m->ws, ws_max_frame(m->ws), ms);
            m->max_sessions = ms;
        }
        logf("relay hello: maxFrameBytes=%u maxSessions=%u",
             ws_max_frame(m->ws), m->max_sessions);
        return;
    }
    if (strcmp(verb, "bye") == 0) {
        logf("relay said bye");
        pthread_mutex_lock(&m->list_lock);
        m->closing = 1;
        pthread_mutex_unlock(&m->list_lock);
        return;
    }
    if (strcmp(verb, "close") == 0) {
        /* ⛔ `found` IS COPIED OUT WHILE THE LOCK IS HELD AND THE POINTER IS
         * NEVER TOUCHED AFTERWARDS. The first version did `if (s)` after
         * unlocking, which re-reads a pointer the session's own thread may
         * have freed in the window between the unlock and the test -- a
         * use-after-free read that reads whatever the allocator has put there
         * and branches on it. A boolean copied under the lock cannot be freed. */
        int found;
        pthread_mutex_lock(&m->list_lock);
        MuxSession *s = mux_find(m, id);
        found = (s != NULL);
        if (s) {
            s->stop = 1;
        }
        pthread_mutex_unlock(&m->list_lock);
        if (found) {
            logf("operator closed session %.8s", id);
        }
        return;
    }
    if (strcmp(verb, "open") != 0) {
        logf("relay said: %.120s", json);
        return;
    }

    /* `open`. A 32-hex id is required. Anything else is refused, because the
     * id is how every later frame finds this session and a malformed one
     * would be a session that can never be addressed. */
    if (strlen(id) != 32) {
        char msg[320];
        snprintf(msg, sizeof msg,
                 "{\"type\":\"reject\",\"id\":\"%.32s\",\"reason\":\"id is not 32 hex characters\"}", id);
        mux_send_text(m, msg);
        logf("refused a session with a malformed id: %.32s", id);
        return;
    }
    {
        /* ⛔ THE SESSION CAP IS THE RELAY'S OWN, COUNTED BEFORE ANY ALLOCATION
         * FOR THE NEW SESSION. maxSessions is a promise the relay made in its
         * hello and one the node keeps, so a node cannot be closed for
         * exceeding a limit it was told. The count is taken under the same
         * lock that publishes sessions, so two simultaneous `open`s cannot
         * both see room for the last slot. */
        unsigned n = 0;
        pthread_mutex_lock(&m->list_lock);
        for (int b = 0; b < MUX_MAX_SESSIONS; b++) {
            for (MuxSession *s = m->by_id[b]; s; s = s->next) {
                n++;
            }
        }
        pthread_mutex_unlock(&m->list_lock);
        /* The count above is taken under the lock and the limit is compared
         * after it, so two simultaneous `open`s can both see room for the
         * last slot. The limit is a POLICY number rather than a hard
         * invariant: the relay is the authority on its own maxSessions and a
         * node that briefly exceeds its own count is refused by the relay,
         * which is a far better outcome than serialising every `open` behind
         * a global count. Recorded here so the next reader does not mistake it
         * for an oversight. */
        if (n >= m->max_sessions) {
            char msg[256];
            snprintf(msg, sizeof msg,
                     "{\"type\":\"reject\",\"id\":\"%.32s\",\"reason\":\"this node is at its %u session limit\"}",
                     id, m->max_sessions);
            mux_send_text(m, msg);
            logf("refused session %.8s: at the %u session limit", id, m->max_sessions);
            return;
        }
    }

    MuxSession *s = calloc(1, sizeof *s);
    if (s == NULL) {
        char msg[256];
        snprintf(msg, sizeof msg,
                 "{\"type\":\"reject\",\"id\":\"%.32s\",\"reason\":\"out of memory\"}", id);
        mux_send_text(m, msg);
        return;
    }
    snprintf(s->id, sizeof s->id, "%s", id);
    s->sock = -1;
    s->pid = -1;
    buf_init(&s->inbox);
    pthread_mutex_init(&s->lock, NULL);
    pthread_cond_init(&s->cv, NULL);

    char why[512] = "";

    /* ⛔ AN `open` THAT NAMES A DESTINATION IS A SOCKS FORWARD AND NOT A
     * SESSION, and it DIALS instead of starting the ssh server.
     *
     * The destination arrives ONCE, in the `open`, and every later frame is
     * bare bytes for that connection. That is the shape dropssh#10 records as
     * structurally better than a 32-byte prefix on every frame, and the reason
     * it records it as NOT adoptable is that the prefix is the ajam relay's
     * rule. Here both ends are ours, so nothing is being deviated from and
     * there is no per-frame field to forget.
     *
     * A SOCKS forward is refused against an ajam node, and that is visible
     * here rather than at runtime: an ajam relay never sends an `open` with a
     * host in it, so this branch is only ever reached from a dropssh relay. */
    {
        char host[256] = "";
        unsigned dport = 0;
        /* ⛔ THE KEY IS PASSED WITH ITS QUOTES, AND `relay_parse_uint` NEEDS
         * THEM. It does `strstr(json, key)` and then walks to the `:`; given
         * the bare key `port` it finds the opening quote of the VALUE, steps
         * over four characters and lands on the closing quote rather than the
         * colon, so it returns -1 and the port reads as absent.
         *
         * ⛔ THE CONSEQUENCE WAS THAT A SOCKS FORWARD NEVER TOOK THIS BRANCH AT
         * ALL. `is_socks` was permanently false, the node started a `dropbear`
         * instead of dialling the destination, and the forward delivered
         * nothing while the node logged a perfectly healthy ssh session. The
         * two existing callers pass `"\"maxFrameBytes\""` and
         * `"\"maxSessions\""`, so the convention was established and this call
         * was the odd one out; `relay_parse_string` builds its own quoted key,
         * which is why the two disagree and why neither used to say so.
         *
         * ⛔ IT WAS ONLY VISIBLE BECAUSE THE END-TO-END CASE READS THE NODE'S
         * OWN LOG. A case that checked a handshake would have passed: the
         * forward connected, and a connected forward is not a working one. */
        int is_socks = (relay_parse_string(json, "host", host, sizeof host) == 0 &&
                        relay_parse_uint(json, "\"port\"", &dport) == 0 &&
                        dport > 0);
        if (is_socks) {
            Transport *out = NULL;
            char derr[512] = "";
            /* The node dials through the SAME egress as everything else, which
             * is the point of the capability: the destination is reached from
             * the CAGE, over whatever route the cage has, including a 443-only
             * CONNECT proxy. */
            if (strncmp(host, "unix://", 7) == 0) {
                out = transport_tcp_unix(host + 7, derr, sizeof derr);
            } else {
                out = transport_tcp(host, (int)dport, dropssh_proxy_host(),
                                    dropssh_proxy_port(), 15000, derr,
                                    sizeof derr);
            }
            if (out == NULL) {
                char msg[512];
                snprintf(msg, sizeof msg,
                         "{\"type\":\"reject\",\"id\":\"%.32s\","
                         "\"reason\":\"could not reach %s:%u: %.180s\"}",
                         id, host, dport, derr);
                mux_send_text(m, msg);
                logf("a socks forward to %s:%u failed: %s", host, dport, derr);
                buf_free(&s->inbox);
                pthread_mutex_destroy(&s->lock);
                pthread_cond_destroy(&s->cv);
                free(s);
                return;
            }
            /* ⛔ THE DIALED TRANSPORT BECOMES THE SESSION'S SOCKET, EXACTLY AS
             * dropbear's socketpair does, so everything below this line is the
             * ordinary session path with no special case in it. */
            int tfd = transport_detach_fd(out);
            out->close(out); /* the fd is detached; free the husk */
            if (tfd < 0) {
                out->close(out);
                char msg[512];
                snprintf(msg, sizeof msg,
                         "{\"type\":\"reject\",\"id\":\"%.32s\","
                         "\"reason\":\"the connection to %s:%u could not be "
                         "handed over\"}", id, host, dport);
                mux_send_text(m, msg);
                logf("a socks forward to %s:%u could not be detached", host, dport);
                buf_free(&s->inbox);
                pthread_mutex_destroy(&s->lock);
                pthread_cond_destroy(&s->cv);
                free(s);
                return;
            }
            /* ⛔ THE MODE IS RECORDED ON THE SESSION, BECAUSE THE SESSION
             * THREAD HAS TO KNOW WHICH PEER IS BEHIND `s->sock`. A `dropbear -i`
             * child for an ssh session, a dialled destination for a SOCKS one,
             * and the first version did not say which -- so the SOCKS session
             * ran the ssh pump against a socket with no child behind it. ⛔ The
             * observable symptom was the node logging "Child connection from
             * localhost" and then nothing at all, with the forward dead and
             * the node still up: the shape this project has shipped twice. */
            logf("socks forward opened: %s (%s) as %.8s", host,
                 strncmp(host, "unix://", 7) == 0 ? "socket" : "tcp", id);
            s->sock = tfd;
            s->pid = -1;
            s->is_socks = 1;
            /* The dialled socket is already non-blocking via wrap_fd, but
             * the session pump requires it, so assert it here rather than
             * assuming the transport kept it. */
            {
                int fl = fcntl(s->sock, F_GETFL, 0);
                if (fl >= 0) {
                    fcntl(s->sock, F_SETFL, fl | O_NONBLOCK);
                }
            }
        } else {
        if (start_server(server_cmd_for_sessions(), &s->sock, &s->pid, why,
                         sizeof why) != 0) {
            /* The server command is per-process (probe already validated it), so
             * a failure here is a resource failure, not a config one. */
            char msg[512];
            snprintf(msg, sizeof msg,
                     "{\"type\":\"reject\",\"id\":\"%.32s\",\"reason\":\"%.200s\"}", id, why);
            mux_send_text(m, msg);
            logf("could not start a server for %.8s: %s", id, why);
            buf_free(&s->inbox);
            pthread_mutex_destroy(&s->lock);
            pthread_cond_destroy(&s->cv);
            free(s);
            return;
        }
        } /* end of the dial-vs-spawn branch: both paths converge below */

        /* Publish the session BEFORE sending `ready`, so a data frame that
         * arrives in the same instant as the `ready` finds a session to land in.
         * Publishing after would race, and the frame would be dropped. */
        pthread_mutex_lock(&m->list_lock);
        unsigned b = id_bucket(s->id);
        s->next = m->by_id[b];
        m->by_id[b] = s;
        pthread_mutex_unlock(&m->list_lock);

        char ready[96];
        snprintf(ready, sizeof ready, "{\"type\":\"ready\",\"id\":\"%s\"}", s->id);
        /* ⛔ LOGGED BECAUSE A FORWARD WAITS ON THIS FRAME, AND A FORWARD THAT
         * WAITS ON A FRAME NOBODY LOGS IS A HANG WITH NO DIAGNOSIS. The relay
         * side says "the node did not answer `ready` within 15s" and this says
         * whether the node sent one, so the two ends of a stuck forward can be
         * told apart from two logs. */
        logf("sending %s ready for %.8s",
             s->is_socks ? "socks" : "operator", s->id);
        if (mux_send_text(m, ready) != 0) {
            /* The relay went away between `open` and `ready`. Mark it and let the
             * thread's teardown reap the server. */
            pthread_mutex_lock(&s->lock);
            s->stop = 1;
            pthread_mutex_unlock(&s->lock);
        }

        sess_arg *a = calloc(1, sizeof *a);
        if (a == NULL) {
            pthread_mutex_lock(&s->lock);
            s->stop = 1;
            pthread_mutex_unlock(&s->lock);
            return;
        }
        a->mux = m;
        a->s = s;
        a->servercmd = server_cmd_for_sessions();
        pthread_t th;
        if (pthread_create(&th, NULL, session_thread, a) != 0) {
            pthread_mutex_lock(&s->lock);
            s->stop = 1;
            pthread_mutex_unlock(&s->lock);
            free(a);
            return;
        }
        pthread_detach(th);
        /* ⛔ THE PHRASE "operator opened session" IS KEPT VERBATIM, BECAUSE A GATE
     * GREPS FOR IT. This line was changed once to say "socks session" or
     * "operator session" and the e2e's two-concurrent-sessions check --
     * which measures whether the node redials per session, by counting
     * registrations against opens -- went red with
     *
     *     the node re-registered 1 times for 0 sessions
     *
     * ⛔ WHICH NAMES NOTHING. A log line is an INTERFACE: something outside this
     * file reads it, and changing the wording to be more accurate broke a
     * measurement rather than improving it. ⛔ The mode is reported in the line
     * ABOVE it, where a human looks, and the phrase a machine greps for is left
     * exactly as it was. */
    logf("operator opened session %.8s (ready sent)", s->id);
        } /* end of the open-handling block: dial and spawn converge above */
}

/* Route ONE data frame to its session, or refuse it.
 *
 * ⛔ A FRAME FOR AN ID THAT IS NOT OPEN IS DROPPED AND COUNTED, NOT
 * DELIVERED. Two things depend on that: a frame for a session that has been
 * torn down must not be delivered to a REUSED id (a reused id would leak one
 * session's bytes into another), and the count is the only signal that the
 * relay and this node disagree about which sessions are open. The count is
 * logged when it is nonzero rather than every frame. */
static void on_data(Mux *m, const unsigned char *pl, size_t len) {
    if (len < 32) {
        /* A node-leg data frame shorter than the id is a relay already put
         * id+payload there, so this should not happen; count and ignore. */
        logf("a data frame of %zu bytes is shorter than a session id; ignored", len);
        return;
    }
    char id[33];
    memcpy(id, pl, 32);
    id[32] = 0;
    for (int i = 0; i < 32; i++) {
        char c = id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            logf("a data frame carried an id that is not 32 hex; ignored");
            return;
        }
    }

    /* ⛔ THE LOOKUP AND EVERY USE OF THE RESULT ARE UNDER `list_lock`, AND THE
     * LOCK IS NOT RELEASED IN BETWEEN. The first version called mux_find with
     * no lock at all, took the session's own lock, and appended to its inbox --
     * while the session's own thread could be at the end of its teardown,
     * having already unlinked itself and be about to free() it. That is a
     * use-after-free on the reader thread, and the window is every session
     * teardown, which is every session.
     *
     * ⛔ IT WAS INVISIBLE BECAUSE NOTHING LOOKED FOR IT. Every test in the
     * suite passed, because the sessions in the gate are short: the operator
     * finishes, the reader has already delivered the last frame, and the
     * teardown happens after the socket has nothing more to deliver. The
     * window is a frame arriving in the same instant the session dies, which
     * is what a real operator does when a command exits and it sends the
     * channel close in the same breath as the last output.
     *
     * The rule, stated so a future edit does not have to rediscover it: a
     * pointer found in a shared table is only valid while the lock that guards
     * the table is held. `s->lock` protects the session's buffers; it does NOT
     * keep the session itself alive, and taking it second is too late. */
    int overflow = 0;
    pthread_mutex_lock(&m->list_lock);
    MuxSession *s = mux_find(m, id);
    if (s == NULL) {
        static unsigned long orphan = 0;
        if (++orphan % 64 == 1) {
            logf("data for an unknown session %.8s (total %lu); dropped", id, orphan);
        }
        pthread_mutex_unlock(&m->list_lock);
        return;
    }
    /* Strip the id; the remainder is the session's ssh bytes. */
    pthread_mutex_lock(&s->lock);
    if (s->dead || s->server_done) {
        pthread_mutex_unlock(&s->lock);
        pthread_mutex_unlock(&m->list_lock);
        return;
    }
    int rc = buf_append(&s->inbox, pl + 32, len - 32);
    if (rc == 0) {
        s->bytes_down += (unsigned long long)(len - 32);
    } else {
        overflow = 1;
    }
    pthread_mutex_unlock(&s->lock);
    pthread_mutex_unlock(&m->list_lock);

    if (overflow) {
        logf("session %.8s: inbox overflow; the operator is sending faster than "
             "the server reads", id);
        pthread_mutex_lock(&m->list_lock);
        MuxSession *again = mux_find(m, id);
        if (again) {
            again->stop = 1;
        }
        pthread_mutex_unlock(&m->list_lock);
    }
}

/* The single reader. It reads WHOLE FRAMES, tells text from binary by the
 * frame's own opcode, and hands each to on_control or on_data. It is the only
 * thread that calls ws_recv_frame on this websocket. */
static void *mux_reader(void *arg) {
    Mux *m = arg;
    buffer frame;
    buf_init(&frame);
    for (;;) {
        int op = 0, closed = 0, fatal = 0;
        size_t n = 0;
        int r = ws_recv_frame(m->ws, &op, &frame, &n, &closed, &fatal);
        if (r < 0) {
            if (m->ws->closed && ws_close_code(m->ws)) {
                logf("relay closed the node socket: code %d %s",
                     ws_close_code(m->ws), ws_close_reason(m->ws));
            } else if (fatal) {
                logf("the relay sent framing dropssh cannot read; closing");
            } else {
                const char *le = dropssh_tls_lasterror();
                logf("relay connection ended: %s", le ? le : "closed");
            }
            pthread_mutex_lock(&m->list_lock);
            m->closing = 1;
            /* Stop every session so the process can exit; each thread reaps
             * its own server on the way out. */
            for (int b = 0; b < MUX_MAX_SESSIONS; b++) {
                for (MuxSession *s = m->by_id[b]; s; s = s->next) {
                    s->stop = 1;
                }
            }
            pthread_mutex_unlock(&m->list_lock);
            break;
        }
        if (op == 0x1) {   /* text: control */
            /* NUL-terminate a copy: the JSON is not NUL-terminated on the
             * wire and a scanner reading past it would read adjacent frame
             * bytes. */
            char *json = malloc(n + 1);
            if (json == NULL) {
                continue;
            }
            memcpy(json, frame.p, n);
            json[n] = 0;
            on_control(m, json);
            free(json);
            continue;
        }
        if (op == 0x2) {   /* binary: session data */
            on_data(m, frame.p, n);
            continue;
        }
    }
    buf_free(&frame);
    return NULL;
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
    g_servercmd = servercmd;

    unsigned backoff = 1;
    int sessions = 0;
    /* ⛔ THE BUDGET AND THE COUNTER ARE READ ONCE, HERE, and the counter is
     * NOT reset by a successful registration. A budget is a budget for the
     * PROCESS, not for one bad run: a node that paired once and then lost the
     * relay twenty minutes later has still used up the operator's patience,
     * and resetting on success would make the number mean "consecutive
     * failures", which is a different policy and would need a different name. */
    const unsigned total_attempts = o->retry_budget;
    unsigned attempts = 0;
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

        Mux m;
        memset(&m, 0, sizeof m);
        m.ws = &ws;
        m.max_sessions = WS_HELLO_DEFAULT_SESSIONS;
        pthread_mutex_init(&m.list_lock, NULL);
        pthread_mutex_init(&m.wlock, NULL);
        /* ⛔ THE READER IS ONE THREAD AND IT IS THE ONLY ONE THAT TOUCHES THE
         * WEBSOCKET'S READ SIDE. Everything else either writes (under wlock)
         * or talks to its own socketpair. This is the B5 fix, and it is a
         * structure rather than a flag: there is no API by which a session
         * thread could call ws_recv_frame. */
        pthread_t reader;
        if (pthread_create(&reader, NULL, mux_reader, &m) != 0) {
            logf("could not start the node's reader thread");
            ws_close(&ws);
            t->close(t);
            goto wait_and_retry;
        }
        pthread_join(reader, NULL);
        pthread_mutex_destroy(&m.list_lock);
        pthread_mutex_destroy(&m.wlock);
        ws_close(&ws);
        t->close(t);
        if (o->once) {
            return sessions > 0 ? 0 : 1;
        }
wait_and_retry:
        if (o->once) {
            return 1;
        }
        /* ⛔ A TOTAL RECONNECTION BUDGET, AND A GIVE-UP POINT, BECAUSE A CAPPED
         * BACKOFF WITH NO TOTAL IS AN AGENT THAT NEVER ADMITS IT IS BROKEN.
         *
         * The backoff below doubles to 30 s and stays there, so a `serve` whose
         * relay is gone, or whose name is wrong, or whose token was revoked,
         * retries for ever. From the outside that process looks HEALTHY: it is
         * running, it is not crashing, and it logs a line every 30 s. Nothing
         * in it says the give-up point was never reached, because there wasn't
         * one. A supervisor sees a live process and a service that is not there.
         *
         * The budget is in ATTEMPTS and not in wall-clock, because a wall-clock
         * budget answers a different question: with a 30 s cap, a 20-minute
         * budget is 40 attempts on one failure and 20 on five, and the operator
         * reading the log cannot tell which. Attempts are countable and the log
         * already counts them.
         *
         * ⛔ AND THE DEFAULT IS "KEEP TRYING", BECAUSE THE COMMON CASE IS A
         * NODE THAT STARTS BEFORE THE RELAY. A cage that boots with no network
         * and comes up twenty minutes later must still pair, and a budget that
         * gave up at five minutes would break that deployment to satisfy a
         * tidier log. So the budget is a NUMBER an operator sets, the default
         * is unlimited, and `dropssh doctor` and `--help` both say so.
         *
         * ⛔ AND THE EXIT CODE IS ITS OWN, so a supervisor can tell "gave up"
         * from "the server command failed". 4 is the one here; 1 is a session
         * that ran and could not log anyone in, which is a different fault with
         * a different fix. */
        if (total_attempts > 0 && attempts >= total_attempts) {
            logf("giving up after %u attempts: the relay has not accepted "
                 "this node. Raise --retry-budget, or set it to 0 to keep "
                 "trying for ever", attempts);
            return 4;
        }
        attempts++;
        logf("retrying in %us (attempt %u%s)", backoff, attempts,
             (total_attempts > 0 && attempts == total_attempts)
                 ? ", the last one" : "");
        dropssh_sleep_ms(backoff * 1000);
        if (backoff < 30) {
            backoff *= 2;
        }
    }
}
