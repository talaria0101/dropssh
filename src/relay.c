/* relay.c - a rendezvous relay, for a deployment that runs its own.
 *
 * WHY THIS EXISTS WHEN THERE IS ALREADY A RELAY. Two reasons, and the second
 * one is about being able to prove anything at all:
 *
 *   1. A self-hosted cage should not depend on a third party's uptime to get
 *      a shell back into its own machine.
 *   2. The e2e needs a relay on loopback that answers in a millisecond, so a
 *      change to the transport is provable without a network and without
 *      anyone's availability. A transport that can only be tested against a
 *      remote service is a transport whose breakage is discovered by a user.
 *
 * ⛔ IT IS A RENDEZVOUS AND NOT A FORWARD, AND THE TWO ARE NOT INTERCHANGEABLE.
 * A rendezvous pairs two named peers that both dial it, so the last hop is one
 * of the two ends. A forward has the relay dial the target itself, so the last
 * hop is the relay. They differ in exactly which hop is last and they take
 * different arguments, and pairing a client with no node waiting is the
 * forward mistake in reverse. This file implements the rendezvous shape and
 * its own help says so, because the other shape exists.
 *
 * ⛔ IT IS A CIPHERTEXT PIPE. It never decrypts, never authenticates the ssh
 * inside, and has no opinion about it. The ssh host key is the only identity
 * in a session and the ssh client verifies it, not this.
 *
 * THE PAIRING IS: the node thread owns its WsSession and is the one that
 * splices, because a session has one owner and two threads splicing the same
 * WsSession would be a data race on its read buffer. The client thread waits
 * to be told the session is over and then closes its own copy.
 */
#include "dropssh.h"
#include "transport.h"
#include "ws.h"
#include "util.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define RELAY_MAX_NAMES 32
#define RELAY_NAME_MAX  64

typedef struct entry {
    char      name[RELAY_NAME_MAX];
    int       used;
    WsSession *node;        /* the node's session, when it is waiting */
    WsSession *client;      /* a client waiting for that node */
    int       in_session;   /* a splice is running for this name */
    pthread_cond_t cv;
} entry;

static entry table[RELAY_MAX_NAMES];
static pthread_mutex_t tlock = PTHREAD_MUTEX_INITIALIZER;
static const char *only_name = NULL;

static void logf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "dropssh relay: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    fflush(stderr);
}

static entry *slot_locked(const char *name, int create) {
    for (int i = 0; i < RELAY_MAX_NAMES; i++) {
        if (table[i].used && strcmp(table[i].name, name) == 0) {
            return &table[i];
        }
    }
    if (!create) {
        return NULL;
    }
    for (int i = 0; i < RELAY_MAX_NAMES; i++) {
        if (!table[i].used) {
            snprintf(table[i].name, sizeof table[i].name, "%s", name);
            table[i].used = 1;
            table[i].node = NULL;
            table[i].client = NULL;
            table[i].in_session = 0;
            pthread_cond_init(&table[i].cv, NULL);
            return &table[i];
        }
    }
    return NULL;
}

/* A directional copy between two websocket sessions. */
typedef struct { WsSession *from, *to; } leg;

static void *leg_run(void *arg) {
    leg *l = arg;
    for (;;) {
        unsigned char buf[16384];
        int closed = 0;
        int n = ws_read(l->from, buf, sizeof buf, &closed);
        if (n < 0) {
            break;
        }
        if (n == 0) {
            if (closed) {
                break;
            }
            continue;
        }
        if (ws_write(l->to, buf, (size_t)n) != 0) {
            break;
        }
    }
    return NULL;
}

/* The splice runs on the node thread, which owns one of the two sessions. Both
 * directions are threads so neither side waits on the other; an ssh session is
 * a long conversation in both directions and a half-duplex loop would stall
 * it the first time one side had nothing to say. */
static int splice(WsSession *a, WsSession *b) {
    leg la = { a, b }, lb = { b, a };
    pthread_t ta, tb;
    if (pthread_create(&ta, NULL, leg_run, &la) != 0) {
        return -1;
    }
    if (pthread_create(&tb, NULL, leg_run, &lb) != 0) {
        pthread_join(ta, NULL);
        return -1;
    }
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    return 0;
}

/* A blocking HTTP answer, for a refusal that happens before the upgrade. */
static void refuse(Transport *t, int status, const char *why) {
    char resp[512];
    int rn = snprintf(resp, sizeof resp,
                      "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\n"
                      "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                      status, why, strlen(why), why);
    if (rn > 0) {
        t->write(t, resp, (size_t)rn);
    }
}

static void *conn_thread(void *arg) {
    int fd = (int)(intptr_t)arg;
    Transport *t = transport_from_fd(fd, "relay");
    if (t == NULL) {
        close(fd);
        return NULL;
    }
    WsSession ws;
    ws_status st;
    memset(&st, 0, sizeof st);
    char path[512] = "";
    if (ws_server(t, &ws, path, sizeof path, &st) != 0) {
        logf("upgrade refused: %s", ws_strerror(&st));
        ws_close(&ws);
        return NULL;
    }
    const char *name = NULL;
    int is_node = 0;
    /* ⛔ BOTH SPELLINGS ARE ACCEPTED, AND THE LOCAL RELAY MATCHES THE REMOTE
     * ONE'S PATHS. The ajam relay serves /v1/node/<name> and
     * /v1/connect/<name>; the first version of this relay used /node/ and
     * /connect/, so `dropssh serve --name x` registered against a local relay
     * and then sat there, and the only symptom was `dropssh connect` closing
     * with nothing in any log. A relay that answers a different path is a
     * relay you have to configure differently, and the whole point of
     * shipping one is that the command line does not change with the relay.
     */
    if (strncmp(path, "/v1/node/", 9) == 0) {
        name = path + 9;
        is_node = 1;
    } else if (strncmp(path, "/node/", 6) == 0) {
        name = path + 6;
        is_node = 1;
    } else if (strncmp(path, "/v1/connect/", 12) == 0) {
        name = path + 12;
    } else if (strncmp(path, "/connect/", 9) == 0) {
        name = path + 9;
    } else {
        refuse(t, 404, "unknown path: this relay serves /v1/node/<name> and "
                      "/v1/connect/<name>\n");
        ws_close(&ws);
        return NULL;
    }
    if (name[0] == 0 || strlen(name) >= RELAY_NAME_MAX) {
        refuse(t, 400, "a node name is required and must be short\n");
        ws_close(&ws);
        return NULL;
    }
    if (only_name && strcmp(name, only_name) != 0) {
        char m[256];
        snprintf(m, sizeof m, "this relay admits only the name %s\n", only_name);
        refuse(t, 403, m);
        ws_close(&ws);
        return NULL;
    }

    if (is_node) {
        pthread_mutex_lock(&tlock);
        entry *e = slot_locked(name, 1);
        if (e == NULL) {
            pthread_mutex_unlock(&tlock);
            refuse(t, 503, "this relay is full\n");
            ws_close(&ws);
            return NULL;
        }
        if (e->node != NULL || e->in_session) {
            pthread_mutex_unlock(&tlock);
            refuse(t, 409, "a node with that name is already connected\n");
            ws_close(&ws);
            return NULL;
        }
        e->node = &ws;
        pthread_mutex_unlock(&tlock);
        logf("node %s waiting", name);

        /* Wait for a client. The timeout is a backstop, not a policy: a client
         * that never comes should not leave a node registered forever, but a
         * client that takes its time to type a password must not be cut off.
         * A node re-dials immediately, so a wait that ends early costs one
         * websocket and nothing else. */
        pthread_mutex_lock(&tlock);
        e = slot_locked(name, 0);
        unsigned waited = 0;
        while (e && e->client == NULL && !e->in_session && waited < 3600000u) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 5;
            pthread_cond_timedwait(&e->cv, &tlock, &ts);
            waited += 5000;
        }
        WsSession *client = NULL;
        if (e && e->client) {
            client = e->client;
            e->client = NULL;
            e->in_session = 1;
        }
        pthread_mutex_unlock(&tlock);

        if (client == NULL) {
            logf("node %s: no client arrived", name);
            pthread_mutex_lock(&tlock);
            e = slot_locked(name, 0);
            if (e && e->node == &ws) {
                e->node = NULL;
            }
            pthread_mutex_unlock(&tlock);
            ws_close(&ws);
            return NULL;
        }
        logf("node %s paired with a client", name);
        splice(&ws, client);
        logf("node %s session ended", name);
        pthread_mutex_lock(&tlock);
        e = slot_locked(name, 0);
        if (e) {
            e->in_session = 0;
            e->node = NULL;
            pthread_cond_broadcast(&e->cv);
        }
        pthread_mutex_unlock(&tlock);
        /* The client's copy is closed by its own thread; this one is the node's. */
        ws_close(&ws);
        return NULL;
    }

    /* ⛔ THE CLIENT ALWAYS ENQUEUES AND WAITS, AND NEVER TOUCHES THE NODE.
     *
     * The first version of this branch tried to be clever: if a node was
     * already waiting it took the node's pointer and spliced on the client's
     * thread. That is a data race, because the node's WsSession lives on the
     * node thread's stack and that thread is a participant in the pairing. The
     * symptom was precise and misleading: the relay logged "client paired
     * with waiting node" and then "node: no client arrived" a moment later,
     * because the client had nulled e->node before the node thread woke, so
     * the node thread found nothing to pair with and the session died in the
     * gap.
     *
     * One owner per session fixes it. The node thread owns the node's session
     * and is the only one that splices it. A client parks its own session in
     * the slot and waits to be told the session is over. Whichever arrives
     * second wakes the other, and the pairing happens in exactly one place.
     */
    pthread_mutex_lock(&tlock);
    entry *e = slot_locked(name, 1);
    if (e == NULL) {
        pthread_mutex_unlock(&tlock);
        refuse(t, 503, "this relay is full\n");
        ws_close(&ws);
        return NULL;
    }
    if (e->client != NULL) {
        pthread_mutex_unlock(&tlock);
        refuse(t, 409, "another client is already waiting for that name\n");
        ws_close(&ws);
        return NULL;
    }
    e->client = &ws;
    int node_waiting = (e->node != NULL);
    pthread_cond_broadcast(&e->cv);
    pthread_mutex_unlock(&tlock);
    logf("client waiting for node %s (node already here: %s)", name,
         node_waiting ? "yes" : "no");

    /* Wait for the node thread to take this session and finish with it. The
     * two phases are distinct and both are waited on: first for the pairing
     * to start, then for it to end, because a client that returned as soon as
     * it was paired would close its own websocket out from under a session
     * that is still running. */
    pthread_mutex_lock(&tlock);
    e = slot_locked(name, 0);
    unsigned waited = 0;
    while (e && e->client == &ws && waited < 3600000u) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        pthread_cond_timedwait(&e->cv, &tlock, &ts);
        waited += 5000;
    }
    int paired = e && e->client != &ws;
    if (paired) {
        while (e && e->in_session && waited < 3600000u) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 5;
            pthread_cond_timedwait(&e->cv, &tlock, &ts);
            waited += 5000;
        }
    }
    pthread_mutex_unlock(&tlock);
    if (paired) {
        logf("client session with %s ended", name);
    } else {
        logf("client: no node %s arrived", name);
        pthread_mutex_lock(&tlock);
        e = slot_locked(name, 0);
        if (e && e->client == &ws) {
            e->client = NULL;
        }
        pthread_mutex_unlock(&tlock);
    }
    ws_close(&ws);
    return NULL;
}

int dropssh_relay_main(int argc, char **argv) {
    const char *listen_path = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            listen_path = argv[++i];
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            only_name = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fprintf(stderr,
"dropssh relay - a rendezvous relay (rendezvous, not forward)\n"
"\n"
"  --listen unix:///path.sock   listen on a unix socket (default when no\n"
"                              --listen is given: unix:///tmp/dropssh.sock)\n"
"  --listen 127.0.0.1:8443      listen on TCP\n"
"  --name N                     admit only this node name\n"
"\n"
"ROLES\n"
"  a node    -> /node/<name>     dials out and waits to be paired\n"
"  a client  -> /connect/<name>  is paired with the waiting node\n"
"\n"
"A RENDEZVOUS pairs two peers that both dial this. It is not a forward\n"
"proxy: it cannot reach a target on a client's behalf. Use `connect --path\n"
"/connect/<host>/<port>` against a forward relay for that.\n");
            return 0;
        }
    }
    signal(SIGPIPE, SIG_IGN);

    int lfd;
    if (listen_path == NULL) {
        listen_path = "unix:///tmp/dropssh.sock";
    }
    if (strncmp(listen_path, "unix://", 7) == 0) {
        const char *path = listen_path + 7;
        unlink(path);
        lfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (lfd < 0) {
            logf("socket: %s", strerror(errno));
            return 1;
        }
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof sa);
        sa.sun_family = AF_UNIX;
        snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);
        if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0) {
            logf("bind %s: %s", path, strerror(errno));
            return 1;
        }
        chmod(path, 0600);
        logf("listening on unix://%s (rendezvous)", path);
    } else {
        char host[128];
        int port = 8443;
        snprintf(host, sizeof host, "%s", listen_path);
        char *c = strrchr(host, ':');
        if (c) {
            *c = 0;
            port = atoi(c + 1);
        }
        lfd = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        sa.sin_addr.s_addr = inet_addr(host[0] ? host : "127.0.0.1");
        if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0) {
            logf("bind %s: %s", host, port ? "" : "", strerror(errno));
            return 1;
        }
        logf("listening on %s:%d (rendezvous)", host, port);
    }
    if (listen(lfd, 16) != 0) {
        logf("listen: %s", strerror(errno));
        return 1;
    }

    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            logf("accept: %s", strerror(errno));
            dropssh_sleep_ms(100);
            continue;
        }
        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &attr, conn_thread, (void *)(intptr_t)fd) != 0) {
            close(fd);
        }
        pthread_attr_destroy(&attr);
    }
}
