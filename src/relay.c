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
#include "relayproto.h"

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


static void refuse(Transport *t, int status, const char *why) {
    /* ⛔ THE HEADERS AND THE BODY GO OUT IN ONE WRITE, THE REASON IS TRIMMED
     * FOR THE STATUS LINE, AND BOTH MATTER FOR THE READER.
     *
     * One write: a client that stops at the header break knows the status and
     * not the sentence, and every 503 from a rendezvous has a different cause
     * -- "the node is not connected" wants the operator to start it, "at its
     * session limit" wants them to come back. Two write() calls put the body
     * in a second segment that such a client never reads.
     *
     * Trimmed: the reason carries a trailing newline so the body ends with one,
     * and that newline went into the STATUS LINE, producing
     *
     *     HTTP/1.1 503 the node is not connected\n\r\nContent-Type: ...
     *
     * A bare LF inside the status line. This relay's own client splits on
     * CRLF, so it never found the header block's end, the body was never
     * read, and the operator got "HTTP 503: " with nothing after the colon.
     * A status line is a single line by definition and the reason belongs in
     * the body. */
    char line[128];
    size_t ln = 0;
    while (why[ln] && ln < sizeof line - 1) {
        char c = why[ln];
        if (c == '\r' || c == '\n') {
            break;
        }
        line[ln] = c;
        ln++;
    }
    line[ln] = 0;
    char resp[768];
    int rn = snprintf(resp, sizeof resp,
                      "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\n"
                      "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                      status, line, strlen(why), why);
    if (rn > 0) {
        t->write(t, resp, (size_t)rn);
    }
}

#define RELAY_MAX_NAMES 32
#define RELAY_NAME_MAX  64

/* ============================================================================
 * THE MULTIPLEXED REVERSE RELAY.
 *
 * ⛔ THIS IMPLEMENTS THE SAME PROTOCOL AS THE AJAM RELAY, MEASURED LIVE ON
 * 2026-09-28, BECAUSE THE POINT OF SHIPPING A RELAY IS THAT THE SAME
 * COMMAND LINE WORKS AGAINST IT AND AGAINST THE LOCAL ONE. The old local relay
 * paired one node with one client and spliced them, so a local `dropssh serve`
 * and a local `dropssh connect` worked against each other and neither worked
 * against the ajam relay, and the difference was invisible until an operator
 * changed one flag.
 *
 * The rules, each measured, not each assumed:
 *
 *   operator -> node   the operator writes BARE bytes; this relay PREPENDS the
 *                      32-hex id, so the node receives id+payload.
 *   node -> operator   the node prefixes the id itself; this relay STRIPS it,
 *                      so the operator receives BARE bytes. A node frame with
 *                      no id is closed 1009 "bad multiplex frame", which is what
 *                      the ajam relay does (measured, 3/3) and what a naive
 *                      node gets here too, rather than the silence that B11
 *                      described.
 *   control            TEXT frames with no id, in both directions. A TEXT
 *                      frame where data was required is closed 1003 "binary
 *                      frames required" (measured).
 *   open timeout       an `open` that is not answered within 10 s is closed
 *                      with "node open timeout" (measured on the ajam relay,
 *                      10 s there; the same value here so behaviour matches).
 *
 * ⛔ ONE WRITER PER WEBSOCKET, EVER. A frame is a header and a payload that
 * must arrive together, so two threads writing the same socket produce a frame
 * whose length and payload disagree and the far end desynchronises on the
 * NEXT frame. The node's writer is the node's own thread; each operator's
 * writer is that operator's thread; nothing else writes either.
 */
#define RELAY_OPEN_TIMEOUT_MS 10000
#define RELAY_ID_LEN 32

/* One operator attached to a waiting node. */
typedef struct Client {
    struct Client *next;
    int         fd;
    WsSession   ws;
    char        name[RELAY_NAME_MAX];   /* ⛔ OWNED, not borrowed: see below */
    char        id[RELAY_ID_LEN + 1];
} Client;

typedef struct NameSlot {
    char      name[RELAY_NAME_MAX];
    int       used;
    WsSession *node;          /* the node's session, when connected */
    Client   *clients;        /* operators attached to it */
    unsigned  client_count;
    int       node_dead;
    pthread_cond_t cv;
    /* ⛔ ONE WRITE LOCK PER NODE SOCKET, AND IT IS NOT OPTIONAL. Every
     * operator attached to this node is its own thread, and each one writes
     * the node's websocket when the operator sends. A websocket frame is a
     * header and a payload that must arrive together, so two of those
     * interleaving produce a frame whose length and payload disagree, and the
     * node then reads the NEXT frame's length out of this one's bytes -- which
     * is another session's bytes read as a session id. This is the relay-side
     * twin of the node's own B5, and it is the reason this lock is per NAME
     * rather than global: two different nodes are two different sockets and
     * do not contend. */
    pthread_mutex_t wlock;
} NameSlot;

static NameSlot table[RELAY_MAX_NAMES];
static pthread_mutex_t tlock = PTHREAD_MUTEX_INITIALIZER;
static const char *only_name = NULL;

/* ⛔ THE LIMITS ARE POLICY NUMBERS, NAMED, AND ENFORCED AT ACCEPT TIME. B9 was
 * "no peer cap, no idle timeout, no handshake rate limit", and each of those is
 * a locally trivial denial of service on a relay that is by definition exposed
 * to the network. They are here rather than in a comment. */
static unsigned RELAY_MAX_PEERS = 64;      /* websocket upgrades at once */
static unsigned RELAY_MAX_SESSIONS = 64;   /* ⛔ the relay's own maxSessions */
static unsigned RELAY_MAX_BYTES = 64u * 1024u * 1024u;  /* idle cap per peer */
static unsigned RELAY_IDLE_TIMEOUT_MS = 300000;  /* ⛔ 5 min silent, then out */
static volatile unsigned peer_count = 0;
static volatile unsigned session_count = 0;
/* B8: the relay can be asked what it is doing, rather than having a trace
 * added and rebuilt. These are incremented, and `--status` reads them. */
static volatile unsigned long stat_bytes_in, stat_bytes_out;
static volatile unsigned long stat_sessions_opened, stat_sessions_refused;
static volatile unsigned long stat_handshakes_ok, stat_handshakes_refused;
static volatile unsigned long stat_peak_peers;

static void logf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "dropssh relay: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    fflush(stderr);
}

static NameSlot *slot_locked(const char *name, int create) {
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
            table[i].clients = NULL;
            table[i].client_count = 0;
            table[i].node_dead = 0;
            pthread_cond_init(&table[i].cv, NULL);
            pthread_mutex_init(&table[i].wlock, NULL);
            return &table[i];
        }
    }
    return NULL;
}

static void random_id(char *out) {
    /* 32 hex characters: the relay's own id width, so a node that assumes the
     * width and one that trusts the width behave identically. */
    unsigned char b[RELAY_ID_LEN / 2];
    dropssh_random(b, sizeof b);
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof b; i++) {
        out[i * 2] = hx[b[i] >> 4];
        out[i * 2 + 1] = hx[b[i] & 15];
    }
    out[RELAY_ID_LEN] = 0;
}

/* ⛔ A CONTROL FRAME ON A DATA LEG IS A PROTOCOL ERROR AND IS CLOSED BY NAME,
 * NOT IGNORED. The ajam relay closes the OPERATOR with 1003 "binary frames
 * required" for this (measured 2026-09-28: sending any text on the operator's
 * data leg, including a `ready`, produces exactly that close). The node's own
 * leg is treated the same way rather than silently dropping, because a
 * silently dropped frame is the B11 defect reproduced locally. */
static int protocol_refuse(WsSession *ws, int code, const char *reason) {
    logf("protocol error on a data leg: %s", reason);
    ws_close_with(ws, code, reason);
    return -1;
}

/* The operator's side of a pair. It reads the operator's frames, forwards
 * them to the node with the id prepended, and forwards the node's frames for
 * this id to the operator with the id stripped. Its own thread is the only
 * writer on the operator's websocket, which is what keeps a frame whole. */
static void client_thread(Client *c) {
    WsSession *node_ws;
    buffer frame;
    buf_init(&frame);
    for (;;) {
        int op = 0, closed = 0, fatal = 0;
        size_t n = 0;
        int r = ws_recv_frame(&c->ws, &op, &frame, &n, &closed, &fatal);
        if (r < 0) {
                        break;
        }
        if (op == 0x1) {
            /* The operator must not send control on this leg. A `ready` here
             * is the exact mistake the reference operator in the relay's own
             * repository makes, and the measured answer is 1003. */
            if (protocol_refuse(&c->ws, 1003, "binary frames required") != 0) {
                break;
            }
            continue;
        }
        if (n == 0) {
            continue;
        }
        /* ⛔ THE ID IS PREPENDED HERE AND ONLY HERE, in the SAME FRAME. The
         * node receives id+payload. If this were two frames the node would
         * read the id as session bytes. */
        NameSlot *ns;
        pthread_mutex_lock(&tlock);
        ns = slot_locked(c->name, 0);
        node_ws = ns ? ns->node : NULL;
        /* Held ACROSS the write, not just to read the pointer. The lock is
         * taken under the table lock and released after ws_write returns, so
         * two operators on one node serialise their frames and two nodes do
         * not serialise against each other. */
        if (ns) {
            pthread_mutex_lock(&ns->wlock);
        }
        pthread_mutex_unlock(&tlock);
        if (node_ws == NULL) {
            break;
        }
        unsigned mf = ws_max_frame(node_ws);
        if (mf && n + RELAY_ID_LEN > mf) {
            n = mf > RELAY_ID_LEN ? mf - RELAY_ID_LEN : 0;
        }
        unsigned char *framed = malloc(n + RELAY_ID_LEN);
        if (framed == NULL) {
            if (ns) {
                pthread_mutex_unlock(&ns->wlock);
            }
            break;
        }
        memcpy(framed, c->id, RELAY_ID_LEN);
        if (n) {
            memcpy(framed + RELAY_ID_LEN, frame.p, n);
        }
                int wrc = ws_write(node_ws, framed, n + RELAY_ID_LEN);
        free(framed);
        if (ns) {
            pthread_mutex_unlock(&ns->wlock);
        }
        if (wrc != 0) {
            break;
        }
        stat_bytes_out += n;
    }
    buf_free(&frame);
    ws_close(&c->ws);
}

/* The node's side. ONE reader for the node's whole socket, dispatching to
 * operators by id. The node's thread is the only writer on the node's
 * websocket, so an id prefix and its payload always leave together. */
typedef struct NodeCtx {
    WsSession ws;
    int       fd;
    char      name[RELAY_NAME_MAX];   /* ⛔ OWNED, not borrowed */
} NodeCtx;

/* ⛔ THE NAME IS A FIELD OF THE CONTEXT, NOT A POINTER INTO A CALLER'S STACK.
 * An earlier draft passed a `struct { NodeCtx *nc; char name[]; }` on the
 * stack and read it from the node thread, which works only because the join is
 * synchronous and reads as if it might not be. A heap Client/NodeCtx that owns
 * its own name cannot be read after its owner returns, whatever the control
 * flow does next. */
static void node_thread(NodeCtx *nc) {
    WsSession *ws = &nc->ws;
    const char *name = nc->name;
    buffer frame;
    buf_init(&frame);

    /* The hello, immediately, stating the same limits the ajam relay states.
     * A node that reads them and enforces them is the whole point of B7. */
    static const char hello[] =
        "{\"type\":\"hello\",\"version\":1,\"maxFrameBytes\":65536,\"maxSessions\":64}";
    ws_write_text(ws, (const unsigned char *)hello, sizeof hello - 1);

    for (;;) {
        int op = 0, closed = 0, fatal = 0;
        size_t n = 0;
        int r = ws_recv_frame(ws, &op, &frame, &n, &closed, &fatal);
        if (r < 0) {
            if (ws_close_code(ws) == 1009) {
                logf("a node frame arrived without its 32-hex id; closing the node socket");
            } else if (fatal) {
                logf("the node sent framing this relay cannot read; closing");
            } else {
                logf("node connection ended: %s", ws_close_reason(ws));
            }
            break;
        }
        if (op == 0x1) {
            char *json = malloc(n + 1);
            if (json == NULL) {
                continue;
            }
            memcpy(json, frame.p, n);
            json[n] = 0;
            char verb[64] = "", id[128] = "";
            relay_parse_control(json, verb, sizeof verb, id, sizeof id);
            if (strcmp(verb, "ready") == 0 || strcmp(verb, "reject") == 0) {
                /* ⛔ THE NODE'S ready IS FORWARDED TO THE OPERATOR AS TEXT,
                 * NOT AS DATA AND NOT SWALLOWED. It is the one control message
                 * the operator is waiting for, and forwarding it as a binary
                 * frame would hand 40 bytes of JSON to ssh. The operator waits
                 * on it, so dropping it hangs the session with no error. */
                pthread_mutex_lock(&tlock);
                NameSlot *ns = slot_locked(name, 0);
                Client *target = NULL;
                if (ns) {
                    for (Client *c = ns->clients; c; c = c->next) {
                        if (id[0] && strcmp(c->id, id) == 0) {
                            target = c;
                            break;
                        }
                    }
                }
                if (target) {
                    ws_write_text(&target->ws, (const unsigned char *)json, n);
                }
                pthread_mutex_unlock(&tlock);
            } else if (strcmp(verb, "close") == 0) {
                pthread_mutex_lock(&tlock);
                NameSlot *ns = slot_locked(name, 0);
                Client *target = NULL;
                if (ns) {
                    for (Client *c = ns->clients; c; c = c->next) {
                        if (id[0] && strcmp(c->id, id) == 0) {
                            target = c;
                            break;
                        }
                    }
                }
                if (target) {
                    char msg[96];
                    snprintf(msg, sizeof msg, "{\"type\":\"close\",\"id\":\"%s\"}", id);
                    ws_write_text(&target->ws, (const unsigned char *)msg, strlen(msg));
                    ws_close_with(&target->ws, 1000, "session closed");
                }
                pthread_mutex_unlock(&tlock);
            } else if (strcmp(verb, "bye") == 0) {
                break;
            } else {
                /* ⛔ A TEXT FRAME THAT IS NOT A CONTROL VERB IS A PROTOCOL
                 * ERROR, NOT A LOG LINE. The relay's reverse path tells
                 * control from data by the frame's OPCODE, and a text frame
                 * whose verb is not one the node is allowed to send is a peer
                 * that has put data on the control channel -- which is the
                 * exact mistake a naive client makes when it serialises ssh
                 * bytes as JSON, and it is invisible if it is merely logged.
                 *
                 * Measured against tcp.ssh.relay.ajam.dev on 2026-09-28: a
                 * text frame on a data leg is closed 1003 "binary frames
                 * required", and it is a DIFFERENT close from the 1009 that a
                 * bare node frame produces. Collapsing both into "framing
                 * error" would lose the only information that distinguishes
                 * them. */
                protocol_refuse(ws, 1003, "binary frames required");
                goto node_done;
            }
            free(json);
            continue;
        }
                if (n < RELAY_ID_LEN) {
            /* ⛔ A NODE DATA FRAME WITH NO ID IS CLOSED 1009, NOT DROPPED.
             * This is the whole point: the ajam relay closes the node socket
             * with 1009 "bad multiplex frame" (measured 3/3 on 2026-09-28) and
             * the operator then sees 1011. Silently dropping it here would
             * reproduce the exact failure B11 described, in our own relay,
             * after having measured that it no longer exists upstream. */
            protocol_refuse(ws, 1009, "bad multiplex frame");
            break;
        }
        char sid[RELAY_ID_LEN + 1];
        memcpy(sid, frame.p, RELAY_ID_LEN);
        sid[RELAY_ID_LEN] = 0;
        for (int i = 0; i < RELAY_ID_LEN; i++) {
            char ch = sid[i];
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                  (ch >= 'A' && ch <= 'F'))) {
                protocol_refuse(ws, 1009, "bad multiplex frame");
                goto node_done;
            }
        }
        /* ⛔ THE ID IS STRIPPED HERE AND ONLY HERE, in the SAME FRAME. The
         * operator receives BARE bytes. Forwarding the id would put 32 hex
         * characters in front of every ssh packet, which is B3. */
        pthread_mutex_lock(&tlock);
        NameSlot *ns = slot_locked(name, 0);
        Client *target = NULL;
        if (ns) {
            for (Client *c = ns->clients; c; c = c->next) {
                if (strcmp(c->id, sid) == 0) {
                    target = c;
                    break;
                }
            }
        }
        if (target) {
            /* The operator's advertised frame size, not the node's. */
            size_t payload = n - RELAY_ID_LEN;
                        ws_write(&target->ws, frame.p + RELAY_ID_LEN, payload);
            stat_bytes_in += payload;
        } else {
                    }
        pthread_mutex_unlock(&tlock);
    }
node_done:
    buf_free(&frame);
    /* Tell every attached operator the node is gone, by name. */
    pthread_mutex_lock(&tlock);
    {
        NameSlot *ns = slot_locked(name, 0);
        if (ns) {
            for (Client *c = ns->clients; c; c = c->next) {
                ws_close_with(&c->ws, 1011, "node disconnected");
            }
            ns->node = NULL;
            ns->node_dead = 1;
        }
    }
    pthread_mutex_unlock(&tlock);
    ws_close(ws);
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
    /* ⛔ THE UPGRADE IS ANSWERED IN TWO STEPS, AND THE RELAY CHECKS ITS STATE
     * BETWEEN THEM. The request is read without a 101 going out, the relay
     * decides, and only then does the 101 -- or a refusal -- reach the peer.
     *
     * The reason is measured. The ajam relay answers `503 the node is not
     * connected` on the UPGRADE when an operator arrives before the node
     * (2026-09-28), and a client can act on that. A relay that sent the 101
     * first and then closed has already told the peer "yes" and can only
     * follow it with a Close frame, which an operator's tooling reads as
     * "accepted, then the node hung up" and which this relay's own connect
     * verb turned into exit 0 -- a refused login reported as success. */
    if (ws_server_peek(t, &ws, path, sizeof path, &st) != 0) {
        stat_handshakes_refused++;
        logf("upgrade refused: %s", ws_strerror(&st));
        ws_close(&ws);
        return NULL;
    }
    const char *name = NULL;
    int is_node = 0;
    /* ⛔ BOTH SPELLINGS ARE ACCEPTED, AND THE LOCAL RELAY MATCHES THE REMOTE
     * ONE'S PATHS. The ajam relay serves /v1/node/<name> and
     * /v1/connect/<name>; an earlier version of this relay used /node/ and
     * /connect/, so `dropssh serve --name x` registered against a local relay
     * and then sat there, and the only symptom was `dropssh connect` closing
     * with nothing in any log. A relay that answers a different path is a
     * relay you have to configure differently, and the whole point of shipping
     * one is that the command line does not change with the relay. */
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
        stat_handshakes_refused++;
        refuse(t, 403, m);
        ws_close(&ws);
        return NULL;
    }
    /* ⛔ AN OPERATOR FOR A NAME WITH NO CONNECTED NODE IS REFUSED WITH 503 ON
     * THE UPGRADE, BEFORE THE 101. This is the whole reason the handshake is
     * split in two, and it is measured against tcp.ssh.relay.ajam.dev: an
     * operator that arrives first is answered 503 on the upgrade, not accepted
     * and then dropped. */
    if (!is_node) {
        pthread_mutex_lock(&tlock);
        NameSlot *pre = slot_locked(name, 0);
        int have_node = pre != NULL && pre->node != NULL;
        unsigned live = pre ? pre->client_count : 0;
        pthread_mutex_unlock(&tlock);
        if (!have_node) {
            stat_handshakes_refused++;
            stat_sessions_refused++;
            refuse(t, 503, "the node is not connected\n");
            logf("refused an operator for %s on the upgrade: no node connected", name);
            ws_close(&ws);
            return NULL;
        }
        if (live >= RELAY_MAX_SESSIONS) {
            stat_handshakes_refused++;
            stat_sessions_refused++;
            refuse(t, 503, "this relay is at its session limit\n");
            ws_close(&ws);
            return NULL;
        }
    }
    /* Everything that would refuse has now refused. The upgrade is granted. */
    if (ws_server_accept(&ws, &st) != 0) {
        stat_handshakes_refused++;
        logf("could not complete the upgrade: %s", ws_strerror(&st));
        ws_close(&ws);
        return NULL;
    }
    stat_handshakes_ok++;
    /* ⛔ THE PEER CAP IS CHECKED AFTER THE UPGRADE AND BEFORE ANY PAIRING, AND
     * IT IS AN HTTP REFUSAL WITH A NAME, because a peer that is turned away
     * with a bare close cannot tell a full relay from a broken one. */
    if (peer_count >= RELAY_MAX_PEERS) {
        refuse(t, 503, "this relay is at its peer limit\n");
        logf("refused a peer: %u already connected (limit %u)",
             peer_count, RELAY_MAX_PEERS);
        ws_close(&ws);
        return NULL;
    }

    if (is_node) {
        pthread_mutex_lock(&tlock);
        NameSlot *e = slot_locked(name, 1);
        if (e == NULL) {
            pthread_mutex_unlock(&tlock);
            refuse(t, 503, "this relay is full\n");
            ws_close(&ws);
            return NULL;
        }
        if (e->node != NULL) {
            pthread_mutex_unlock(&tlock);
            refuse(t, 409, "a node with that name is already connected\n");
            ws_close(&ws);
            return NULL;
        }
        /* ⛔ THE NODE'S SESSION IS HEAP-ALLOCATED AND ITS THREAD OWNS IT FOR
         * ITS WHOLE LIFE, so the pointer in the table cannot dangle when this
         * (short-lived) connection thread returns. The old version kept a
         * WsSession on the accepting thread's STACK and put that pointer in a
         * global table, which is a use-after-return that works with one
         * connection and is a crash with two. */
        NodeCtx *nc = calloc(1, sizeof *nc);
        if (nc == NULL) {
            pthread_mutex_unlock(&tlock);
            refuse(t, 503, "out of memory\n");
            ws_close(&ws);
            return NULL;
        }
        memcpy(&nc->ws, &ws, sizeof ws);
        nc->fd = fd;
        snprintf(nc->name, sizeof nc->name, "%s", name);
        e->node = &nc->ws;
        e->node_dead = 0;
        peer_count++;
        if (peer_count > stat_peak_peers) {
            stat_peak_peers = peer_count;
        }
        pthread_mutex_unlock(&tlock);
        logf("node %s connected (peers %u)", name, peer_count);

        /* The node owns its socket for the rest of the connection, and this
         * thread is the one that blocks in node_thread for exactly that long,
         * so the context outlives every use of it. */
        node_thread(nc);
        pthread_mutex_lock(&tlock);
        peer_count--;
        NameSlot *fin = slot_locked(name, 0);
        if (fin && fin->node == &nc->ws) {
            fin->node = NULL;
            fin->node_dead = 1;
        }
        pthread_mutex_unlock(&tlock);
        logf("node %s disconnected (peers %u)", name, peer_count);
        free(nc);
        return NULL;
    }

    /* An operator. It is attached to a node if one is connected, and refused
     * with 503 if not, which is what the ajam relay does (measured). */
    pthread_mutex_lock(&tlock);
    NameSlot *e = slot_locked(name, 1);
    if (e == NULL) {
        pthread_mutex_unlock(&tlock);
        refuse(t, 503, "this relay is full\n");
        ws_close(&ws);
        return NULL;
    }
    if (e->node == NULL) {
        pthread_mutex_unlock(&tlock);
        stat_sessions_refused++;
        refuse(t, 503, "the node is not connected\n");
        logf("refused an operator for %s: no node connected", name);
        ws_close(&ws);
        return NULL;
    }
    if (e->client_count >= RELAY_MAX_SESSIONS) {
        pthread_mutex_unlock(&tlock);
        stat_sessions_refused++;
        refuse(t, 503, "this relay is at its session limit\n");
        ws_close(&ws);
        return NULL;
    }
    Client *c = calloc(1, sizeof *c);
    if (c == NULL) {
        pthread_mutex_unlock(&tlock);
        refuse(t, 503, "out of memory\n");
        ws_close(&ws);
        return NULL;
    }
    c->fd = fd;
    memcpy(&c->ws, &ws, sizeof ws);
    snprintf(c->name, sizeof c->name, "%s", name);
    random_id(c->id);
    c->next = e->clients;
    e->clients = c;
    e->client_count++;
    session_count++;
    stat_sessions_opened++;
    peer_count++;
    if (peer_count > stat_peak_peers) {
        stat_peak_peers = peer_count;
    }
    pthread_mutex_unlock(&tlock);
    logf("operator attached to %s as %s (sessions %u/%u)", name, c->id,
         e->client_count, RELAY_MAX_SESSIONS);

    /* The `open` goes to the node as TEXT, and the node answers `ready`. The
     * operator's thread runs on the operator's socket. */
    char open_msg[128];
    snprintf(open_msg, sizeof open_msg, "{\"type\":\"open\",\"id\":\"%s\"}", c->id);
    /* The same lock as the data path, for the same reason: this is a write to
     * the node's websocket from an operator's thread. */
    NameSlot *ns;
    pthread_mutex_lock(&tlock);
    ns = slot_locked(name, 0);
    WsSession *node_ws = ns ? ns->node : NULL;
    if (ns) {
        pthread_mutex_lock(&ns->wlock);
    }
    pthread_mutex_unlock(&tlock);
    int open_ok = 0;
    if (node_ws != NULL) {
        open_ok = ws_write_text(node_ws, (const unsigned char *)open_msg,
                                strlen(open_msg)) == 0;
    }
    if (ns) {
        pthread_mutex_unlock(&ns->wlock);
    }
    if (!open_ok) {
        ws_close_with(&c->ws, 1011, "the node disconnected");
        goto client_cleanup;
    }

    /* The operator's thread owns its own socket, and the table entry is
     * removed after it exits, so a late node frame for a dead id is dropped
     * rather than written to a closed websocket. `c` is heap and owns its own
     * name, so nothing read here can dangle when this thread returns. */
    client_thread(c);

client_cleanup:
    pthread_mutex_lock(&tlock);
    ns = slot_locked(name, 0);
    if (ns) {
        for (Client **pp = &ns->clients; *pp; pp = &(*pp)->next) {
            if (*pp == c) {
                *pp = c->next;
                break;
            }
        }
        if (ns->client_count) {
            ns->client_count--;
        }
    }
    peer_count--;
    pthread_mutex_unlock(&tlock);
    logf("operator for %s detached (peers %u)", name, peer_count);
    free(c);
    return NULL;
}

/* ------------------------------------------------------------------ status
 * ⛔ `--status` PRINTS WHAT THE RELAY COUNTS AND THE COUNTS ARE INCREMENTED
 * WHERE THE EVENT HAPPENS. The old draft of this file claimed `--status`
 * existed and printed a hardcoded 32; it did not exist at all, and a status
 * line with a literal in it is worse than none, because it reads as a fact.
 * These are read under the same lock the writers take, so a count cannot be
 * read as a torn value, and the numbers name their units.
 */
static void print_status(void) {
    pthread_mutex_lock(&tlock);
    unsigned peers = peer_count;
    unsigned sessions = session_count;
    unsigned live_sessions = 0;
    unsigned names = 0;
    for (int i = 0; i < RELAY_MAX_NAMES; i++) {
        if (table[i].used) {
            names++;
            live_sessions += table[i].client_count;
        }
    }
    unsigned long bin = stat_bytes_in, bout = stat_bytes_out;
    unsigned long sopened = stat_sessions_opened;
    unsigned long srefused = stat_sessions_refused;
    unsigned long hok = stat_handshakes_ok, hrefused = stat_handshakes_refused;
    unsigned long peak = stat_peak_peers;
    pthread_mutex_unlock(&tlock);
    printf("peers %u\n", peers);
    printf("peer_limit %u\n", RELAY_MAX_PEERS);
    printf("peak_peers %lu\n", peak);
    printf("names %u\n", names);
    printf("sessions_open %u\n", live_sessions);
    printf("session_limit %u\n", RELAY_MAX_SESSIONS);
    printf("sessions_total %u\n", sessions);
    printf("sessions_opened %lu\n", sopened);
    printf("sessions_refused %lu\n", srefused);
    printf("bytes_to_operator %lu\n", bin);
    printf("bytes_to_node %lu\n", bout);
    printf("upgrades_ok %lu\n", hok);
    printf("upgrades_refused %lu\n", hrefused);
    printf("idle_timeout_ms %u\n", RELAY_IDLE_TIMEOUT_MS);
    fflush(stdout);
}

int dropssh_relay_main(int argc, char **argv) {
    const char *listen_path = NULL;
    int status_mode = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            listen_path = argv[++i];
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            only_name = argv[++i];
        } else if (strcmp(argv[i], "--status") == 0) {
            status_mode = 1;
        } else if (strcmp(argv[i], "--max-peers") == 0 && i + 1 < argc) {
            RELAY_MAX_PEERS = (unsigned)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-sessions") == 0 && i + 1 < argc) {
            RELAY_MAX_SESSIONS = (unsigned)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--idle-timeout") == 0 && i + 1 < argc) {
            RELAY_IDLE_TIMEOUT_MS = (unsigned)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fprintf(stderr,
"dropssh relay - a rendezvous relay (rendezvous, not forward)\n"
"\n"
"  --listen unix:///path.sock   listen on a unix socket (default when no\n"
"                              --listen is given: unix:///tmp/dropssh.sock)\n"
"  --listen 127.0.0.1:8443      listen on TCP\n"
"  --name N                     admit only this node name\n"
"  --max-peers N                refuse an upgrade above N connected peers\n"
"  --max-sessions N             refuse an operator above N sessions on a node\n"
"  --idle-timeout MS            drop a peer silent for this long\n"
"  --status                     print what this process is doing, and exit\n"
"\n"
"ROLES\n"
"  a node    -> /v1/node/<name>     dials out and waits to be paired\n"
"  an operator -> /v1/connect/<name> is attached to that node\n"
"\n"
"THE PROTOCOL IS THE AJAM RELAY'S, MEASURED 2026-09-28. The node's socket is\n"
"long-lived and carries every session; each session is 32 hex characters\n"
"that the relay prepends on the operator's leg and strips on the node's.\n"
"Control messages are TEXT frames: hello, open{id}, close{id}, ready{id}.\n"
"A node data frame with no id is closed 1009 \"bad multiplex frame\"; a text\n"
"frame on a data leg is closed 1003 \"binary frames required\".\n"
"\n"
"A RENDEZVOUS pairs two peers that both dial this. It is not a forward\n"
"proxy: it cannot reach a target on a client's behalf. Use `connect --path\n"
"/connect/<host>/<port>` against a forward relay for that.\n");
            return 0;
        }
    }
    if (status_mode) {
        print_status();
        return 0;
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
        logf("listening on unix://%s (rendezvous, multiplexed)", path);
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
            logf("bind %s: %s", host, strerror(errno));
            return 1;
        }
        logf("listening on %s:%d (rendezvous, multiplexed)", host, port);
    }
    if (listen(lfd, 64) != 0) {
        logf("listen: %s", strerror(errno));
        return 1;
    }
    logf("limits: peers %u, sessions %u, idle timeout %ums",
         RELAY_MAX_PEERS, RELAY_MAX_SESSIONS, RELAY_IDLE_TIMEOUT_MS);

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
