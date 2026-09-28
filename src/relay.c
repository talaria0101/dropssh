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
#include "token.h"
#include "transport.h"
#include "ws.h"
#include "util.h"
#include "relayproto.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
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

/* ⛔ THE RELAY'S TOKEN STATE, AND IT IS READ-ONCE, PROCESS-WIDE, AND OPTIONAL.
 *
 * A relay with no key ACCEPTS EVERY TOKEN, and that is the compatibility rule
 * rather than an oversight: `dropssh relay` has always taken no token, serves
 * every session, and a change that began refusing unconfigured peers would
 * break every existing deployment on the first upgrade. A deployment that
 * wants role separation configures a key, and the startup banner and
 * `--status` both say which of the two this process is, because a relay that
 * silently accepted everything while appearing to verify would be worse than
 * either. */
static dropssh_key relay_key;
static unsigned long long relay_pairs_issued = 0;
static unsigned long long relay_tokens_refused = 0;
static unsigned RELAY_PAIR_TTL = 86400;   /* a day; the pair says when it ends */

/* A JSON string value from a body, copied out. ⛔ The bound is the point: this
 * reads a network body into a fixed buffer, and the only field it is ever
 * asked for is a name. */
static int json_field(const char *body, const char *key, char *out,
                      size_t outlen) {
    if (body == NULL || key == NULL || out == NULL || outlen == 0) {
        return -1;
    }
    char pat[64];
    int pn = snprintf(pat, sizeof pat, "\"%s\"", key);
    if (pn <= 0 || (size_t)pn >= sizeof pat) {
        return -1;
    }
    const char *p = strstr(body, pat);
    if (p == NULL) {
        return -1;
    }
    p += pn;
    while (*p == ' ' || *p == '\t' || *p == ':') {
        p++;
    }
    if (*p != '"') {
        return -1;
    }
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o < outlen - 1) {
        /* ⛔ A BACKSLASH IS SKIPPED, NOT EXPANDED. The one field read here is a
         * node name, and a name with a backslash is not a name this relay
         * would ever have issued. Expanding escapes would let a body encode a
         * character the issuer never put in, and the whole claim of the token
         * is that the RELAY chose the name. */
        if (*p == '\\' && p[1]) {
            p++;
        }
        out[o++] = *p++;
    }
    out[o] = 0;
    return o ? 0 : -1;
}

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
    /* ⛔ WHOSE JOB IT IS TO FREE `ws`, AND WHY THAT IS NOT A DETAIL.
     *
     * Two threads can reach the same operator's WsSession: the client's own
     * thread when its socket ends, and the node's thread when the node goes
     * away and every attached operator is told 1011 "node disconnected". The
     * first version let both of them call ws_close, and ws_close frees the
     * session's buffers -- so the second freed memory the first had already
     * freed, and the relay died with
     *
     *     double free or corruption (fasttop)
     *
     * ⛔ WHICH IS THE WORST FAILURE A RELAY CAN HAVE AND THE ONE MOST LIKELY TO
     * BE MISREAD. It happened only on the runs where a node disconnected while
     * an operator was still attached -- the ordinary case of a node being
     * restarted -- and it killed the whole process rather than one session, so
     * every other node and operator on the relay went down with it. A gate that
     * only exercises the happy path does not see it, and neither does a
     * single-session run.
     *
     * So the session is closed ONCE and the flag says which path did it. Both
     * paths still send the close frame -- the operator is told why and its
     * socket is shut -- but only one frees. */
    int         ws_released;
    /* ⛔ WHETHER THE NODE HAS ANSWERED `open` WITH `ready` FOR THIS SESSION.
     * The ajam relay tears the pair down when the operator writes first:
     * operator 1008 "wait for ready", node 1003 "unknown session id"
     * (measured 2026-09-28). Our relay did not, so an operator that wrote
     * early was forwarded to a node socket on which the id did not exist yet
     * -- and the node's own reply, 1009 "bad multiplex frame", named the
     * operator's mistake as the node's.
     *
     * ⛔ WHICH IS THE WORTHLESS VERSION OF THIS BUG. Every party reports
     * something, none of it is the cause, and the one thing that could have
     * said "you were early" said "your frame was malformed". The gate in
     * `connect` is what avoids it, and a client that does not have the gate
     * deserves to be told the truth rather than a symptom.
     *
     * This also fixes a race that existed only here: the node's `ready` is
     * forwarded to the operator from the NODE's thread, and the operator's
     * data is read in the OPERATOR's thread, so without a flag the two
     * threads disagreed about whether the session existed. */
    int         ready_seen;
    /* ⛔ A SOCKS5 REQUEST IS AN OPERATOR, AND IT IS THIS STRUCT RATHER THAN A
     * SECOND DATA PATH BECAUSE OF WHAT IT REUSES.
     *
     * `dropssh#4` (wiretap) and `#8` both name a server-side SOCKS5 that
     * reaches a client. The obvious implementation is a private loop that
     * reads the SOCKS socket and writes to the node's websocket -- and that
     * would be a SECOND way to put bytes on a node's socket, which is the
     * defect this file has produced three double frees and one deadlock over.
     * A frame is a header and a payload that must arrive together, and two
     * writers on one socket produce a frame whose length and payload disagree,
     * which is why `wlock` exists at all.
     *
     * So a SOCKS request becomes an ordinary Client: the same table, the same
     * `client_thread`, the same `ws_write` under the same `wlock`, the same
     * refcount, the same 1011 sweep. The only differences are that its
     * "stdin" is a SOCKS client socket and that its `open` names a
     * destination. There is no second reader on a node's socket, so there is
     * no second framing bug, and none of this needed to be proved by a
     * reasoning exercise about a private loop.
     *
     * `socks_fd` is -1 for every operator that came in over a websocket, and
     * >= 0 for the ones that came in over SOCKS5. `socks_done` records that
     * the SOCKS reply has already been written, so a failure after the reply
     * is not answered twice. */
    int         socks_fd;
    int         socks_done;
    /* ⛔ A REFERENCE COUNT, BECAUSE A POINTER OUT OF THE TABLE IS NOT A
     * REFERENCE TO THE OBJECT.
     *
     * The table lock makes it safe to LOOK a client up; it says nothing about
     * whether the client is still alive when the lock is dropped. Every path
     * that takes a pointer out of `ns->clients` and then does something that
     * can block -- a socket write -- must hold a reference across the gap, or
     * the operator's own thread can free it and the write lands in freed
     * memory.
     *
     * This is not hypothetical in this file: holding the table lock across the
     * write instead deadlocked the relay, and dropping the lock without a
     * reference reintroduces the use-after-free. A refcount is the third
     * option and the only one that is correct for both.
     *
     * `refs` is guarded by `tlock`. The last unref frees, and it does so
     * outside the lock so a free cannot run under it. */
    int         refs;
} Client;



static void client_release(Client *c, int code, const char *reason) {
    if (c->ws_released) {
        return;
    }
    c->ws_released = 1;
    if (code > 0) {
        ws_close_with(&c->ws, code, reason);
    } else {
        ws_close(&c->ws);
    }
}

/* The node's context, declared here because `NameSlot` holds a pointer to it
 * rather than a pointer straight into its websocket. See node_hold. */
typedef struct NodeCtx NodeCtx;

typedef struct NameSlot {
    char      name[RELAY_NAME_MAX];
    int       used;
    /* ⛔ THE NODE IS A `NodeCtx *` AND NOT A `WsSession *`, BECAUSE A BARE
     * POINTER INTO IT IS NOT A REFERENCE TO IT. See node_hold. A reader takes
     * a reference under `tlock` and drops it after the write, which can block;
     * the connection thread frees the NodeCtx on its way out and does so
     * outside every lock this file holds. */
    NodeCtx  *node;          /* the node, when connected */
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

/* ⛔ A REFERENCE IS DROPPED HERE, OUTSIDE ANY LOCK THE CALLER HOLDS, AND THE
 * FREE HAPPENS ONLY IF IT WAS THE LAST ONE.
 *
 * The count is guarded by `tlock` and the free is not under it, because a free
 * that runs while another thread is taking `tlock` to look something up turns
 * a use-after-free into a lock-order inversion, and a lock-order inversion is
 * much harder to read than the bug it replaced. Every path that takes a Client
 * out of the table and then does something that can block holds a reference
 * across the gap, and comes back here.
 */
static void client_unref(Client *c) {
    int last;
    pthread_mutex_lock(&tlock);
    last = (--c->refs <= 0);
    pthread_mutex_unlock(&tlock);
    if (last) {
        free(c);
    }
}
static const char *only_name = NULL;
/* ⛔ THE TOKEN KEY IS A PASSPHRASE, AND IT IS NOT KEPT IN THE OPTION STRUCT OR
 * PRINTED ANYWHERE. The flag is read into a local and turned immediately into
 * a SHA-256 digest; see token.h for why the raw value is not retained. */
static const char *token_key_arg = NULL;
/* The SOCKS listener's three settings, taken from the command line and used
 * once at startup. `--socks` is the LISTEN address, `--socks-node` is the node
 * whose advertised destination is reachable, and `--socks-dest` is that
 * destination. They are three and not one because they answer three different
 * questions -- where do I listen, whose network do I use, and what am I allowed
 * to reach -- and folding them together would make the policy invisible. */
static const char *socks_listen_arg = NULL;
static const char *socks_dest_arg = NULL;
static const char *socks_node_arg = NULL;

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

static void client_release(Client *c, int code, const char *reason);

/* ⛔ A POINTER INTO THE TABLE IS NOT A REFERENCE TO THE OBJECT, AND ON THE NODE
 * SIDE THAT WAS A USE-AFTER-FREE RATHER THAN ONLY A RULE.
 *
 * `NameSlot.node` used to be `WsSession *` -- that is, `&nc->ws`, a pointer
 * INTO a heap NodeCtx. An operator thread did:
 *
 *     lock tlock;  node_ws = ns->node;  lock wlock;  unlock tlock;
 *     ... ws_write_text(node_ws, ...);            <- the NodeCtx may be gone
 *     unlock wlock
 *
 * while the node's own connection thread, on its way out, did `free(nc)` with
 * nothing held. The window is the whole write. `wlock` does not close it: the
 * node's exit path takes only `tlock`, and takes no `wlock` at all, so `wlock`
 * serialises OPERATORS against each other and does nothing to keep the NODE
 * alive. The comment that stood here claimed "the context outlives every use
 * of it", which was true of the node thread's own uses and false of every
 * operator's.
 *
 * `Client` already solved this with a refcount and a table reference. The node
 * gets the same mechanism rather than a second rule, because two rules have to
 * agree and this file has already had three double frees from one rule being
 * applied in one place and forgotten in another.
 *
 * `refs` is guarded by `tlock`. The connection thread's own reference is the
 * one taken when the NodeCtx is published, and node_drop frees on the last
 * unref, outside the lock. */
struct NodeCtx {
    WsSession ws;
    int       fd;
    char      name[RELAY_NAME_MAX];   /* ⛔ OWNED, not borrowed */
    int       refs;
};

/* Take a reference under `tlock`. Returns NULL if there is no node. */
static NodeCtx *node_hold_locked(NameSlot *ns) {
    NodeCtx *nc = ns ? ns->node : NULL;
    if (nc) {
        nc->refs++;
    }
    return nc;
}

static void node_drop(NodeCtx *nc) {
    int last;
    pthread_mutex_lock(&tlock);
    last = (--nc->refs <= 0);
    pthread_mutex_unlock(&tlock);
    if (last) {
        free(nc);
    }
}

/* ⛔ A FAULT-INJECTION POINT, INERT UNLESS `DROPSSH_RELAY_FAULT` NAMES IT.
 *
 * U3 is the 1011 sweep in `node_done` with no reference held, and it was 0/6 on
 * the plant because the window between the sweep taking a `Client *` out of the
 * table and the operator's own thread freeing it is narrower than a probe run
 * can hit. The honest fix for "a race that is too small to hit" is not a
 * bigger race in a loop; it is a way to stand the two threads at the two ends
 * of the window on purpose. That is what this is.
 *
 * The mechanism is a yield, and it is deliberately NOT a sleep: a sleep
 * changes the timing but not the order, so a build with the reference removed
 * still might not fault, and a guard that still might not fault is the thing
 * this project keeps shipping. Yielding at both ends of the window lets the
 * operating system interleave the two threads with high probability while
 * leaving the correctness of the fixed build entirely unchanged -- the
 * reference is what makes the interleaving safe, not the scheduling.
 *
 * ⛔ AND IT IS READ ONCE, AT STARTUP, AND IT IS NOT A PRODUCT FLAG. A
 * concurrency knob on the relay is a knob nobody sets and a path CI depends
 * on, which is the same objection that ruled out a `--silent` mode for the
 * `ready` bound (U1). It is read once into a `const char *`, it names one of
 * two fixed points, and an unrecognised value is a hard error rather than a
 * silently-ignored one, so a typo cannot quietly disable the instrument and
 * turn the case green for the wrong reason. */
static const char *relay_fault_point = NULL;

static void relay_fault(const char *name) {
    if (relay_fault_point == NULL || strcmp(relay_fault_point, name) != 0) {
        return;
    }
    /* A bounded yield, not an unbounded wait: the case must still finish if a
     * future change makes one of the two threads unreachable, and a test that
     * can hang is worse than a test that can fail. */
    for (int i = 0; i < 2000; i++) {
        sched_yield();
    }
}

/* The operator's side of a pair. It reads the operator's frames, forwards
 * them to the node with the id prepended, and forwards the node's frames for
 * this id to the operator with the id stripped. Its own thread is the only
 * writer on the operator's websocket, which is what keeps a frame whole. */
static void client_thread(Client *c) {
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
        /* ⛔ DATA BEFORE `ready` IS REFUSED, AND BOTH ENDS ARE TOLD WHY. The
         * operator is closed 1008 "wait for ready" -- the same code and the
         * same reason the ajam relay uses, measured 2026-09-28 -- and the node
         * is closed 1003 "unknown session id", because from the node's side
         * that is exactly what arrived: a frame for a session that does not
         * exist.
         *
         * The check and the read of the flag are under the table lock, which
         * is the same lock the node's thread takes when it sets the flag, so
         * the two threads cannot disagree. Checking without it would be a race
         * with a window of exactly the size of the `ready` round trip, which is
         * the thing being protected. */
        {
            int early;
            pthread_mutex_lock(&tlock);
            early = !c->ready_seen;
            pthread_mutex_unlock(&tlock);
            if (early) {
                logf("an operator for %s sent session data before the node "
                     "answered `ready`", c->id);
                client_release(c, 1008, "wait for ready");
                NameSlot *ens;
                NodeCtx *enc;
                /* One lookup, one reference, taken under the table lock. The
                 * first version read `ens->node` twice -- once to test it for
                 * NULL and again after taking `wlock` -- and the second read
                 * could see a different node from the first, because the
                 * table's `node` pointer is cleared by the outgoing node's own
                 * thread. Holding the reference is what makes the value
                 * stable across the write, which can block. */
                pthread_mutex_lock(&tlock);
                ens = slot_locked(c->name, 0);
                enc = node_hold_locked(ens);
                if (ens) {
                    pthread_mutex_lock(&ens->wlock);
                }
                pthread_mutex_unlock(&tlock);
                if (enc && ens) {
                    /* ⛔ THE NODE IS *TOLD*, NOT CLOSED, AND THAT IS THE WHOLE
                     * POINT.
                     *
                     * The first version called ws_close_with on the node's
                     * session here. That is a double free waiting to happen and
                     * it is not a maybe: the node's own thread holds the same
                     * WsSession and closes it in its own `node_done`, and this
                     * is a second WsSession's worth of buffers freed by two
                     * paths. Measured on the first run after it was written:
                     *
                     *     free(): double free detected in tcache 2
                     *     Aborted   (the relay)
                     *     Bus error (the node)
                     *
                     * ⛔ AND IT WOULD HAVE TAKEN THE RELAY DOWN, not just the
                     * node, which is the failure mode this file has now produced
                     * twice. The node's socket is written to, with a close
                     * frame, under its write lock -- and the node's thread then
                     * finishes on its own and closes the same session. Nothing
                     * about closing another thread's session is safe, and the
                     * flag that makes it safe for an OPERATOR (`ws_released`)
                     * does not exist on the node's side because the node's
                     * session is owned by exactly one thread: the node's.
                     *
                     * So the node is sent a close FRAME and nothing else. Its
                     * thread sees it, ends its own loop, and closes its own
                     * session -- which is the only place that must happen. A
                     * `close` control message is also forwarded to every other
                     * operator attached to that node, because one operator
                     * arriving early says nothing about the others.
                     *
                     * ⛔ ONE LOOKUP, ONE REFERENCE, ONE LOCK, AND THE SIBLINGS
                     * ARE COLLECTED UNDER `tlock` RATHER THAN WALKED IN PLACE.
                     *
                     * Two things were wrong here and both are the same mistake.
                     * The block read `ens->node` twice -- once to test it for
                     * NULL and again after re-taking `wlock` -- and the two
                     * reads could see DIFFERENT nodes, because the outgoing
                     * node's own thread clears `ns->node` on its way out. And
                     * it walked `ens->clients` with no lock at all, while every
                     * unlink of that list happens under `tlock` in
                     * `client_cleanup`: a sibling detaching mid-walk freed the
                     * Client the next iteration was about to write to.
                     *
                     * So: one reference on the node, held across the node's
                     * write; the siblings collected into a fixed array with a
                     * reference each, under `tlock`; and every write done with
                     * no lock held except the node's own `wlock` around the node
                     * frame itself. This is the shape the 1011 sweep already
                     * uses for exactly the same fan-out. */
                    {
                        char close_msg[96];
                        snprintf(close_msg, sizeof close_msg,
                                 "{\"type\":\"close\",\"id\":\"%s\"}", c->id);
                        ws_write_text(&enc->ws, (const unsigned char *)close_msg,
                                      strlen(close_msg));
                    }
                    pthread_mutex_unlock(&ens->wlock);
                    {
                        Client *sibs[RELAY_MAX_SESSIONS];
                        int nsibs = 0;
                        pthread_mutex_lock(&tlock);
                        for (Client *o = ens->clients;
                             o && nsibs < RELAY_MAX_SESSIONS; o = o->next) {
                            if (o == c) {
                                continue;
                            }
                            o->refs++;
                            sibs[nsibs++] = o;
                        }
                        pthread_mutex_unlock(&tlock);
                        for (int i = 0; i < nsibs; i++) {
                            char m2[96];
                            snprintf(m2, sizeof m2,
                                     "{\"type\":\"close\",\"id\":\"%s\"}", sibs[i]->id);
                            ws_write_text(&sibs[i]->ws,
                                          (const unsigned char *)m2, strlen(m2));
                            client_unref(sibs[i]);
                        }
                    }
                }
                if (enc) {
                    node_drop(enc);
                }
                break;
            }
        }
        /* ⛔ THE ID IS PREPENDED HERE AND ONLY HERE, in the SAME FRAME. The
         * node receives id+payload. If this were two frames the node would
         * read the id as session bytes.
         *
         * ⛔ AND THE NODE IS HELD, NOT MERELY POINTED AT. `wlock` is taken
         * across the write so two operators cannot interleave frames on the
         * node's socket, but `wlock` does NOT keep the node alive: the
         * outgoing node's own thread takes only `tlock` on its way out and
         * then frees the NodeCtx, so a write here could land in freed memory.
         * The reference is taken under the same `tlock` that published the
         * node and dropped after the lock is released, so the NodeCtx outlives
         * the write by exactly as much as it needs to. */
        NameSlot *ns;
        NodeCtx  *enc;
        pthread_mutex_lock(&tlock);
        ns = slot_locked(c->name, 0);
        enc = node_hold_locked(ns);
        if (ns) {
            pthread_mutex_lock(&ns->wlock);
        }
        pthread_mutex_unlock(&tlock);
        if (enc == NULL) {
            if (ns) {
                pthread_mutex_unlock(&ns->wlock);
            }
            break;
        }
        /* ⛔ THE OPERATOR'S FRAME IS FORWARDED WHOLE, AND THIS IS THE FOURTH
         * VERSION OF THIS LINE.
         *
         * The third version truncated to fit the node's advertised
         * `maxFrameBytes`:
         *
         *     if (mf && n + RELAY_ID_LEN > mf) {
         *         n = mf > RELAY_ID_LEN ? mf - RELAY_ID_LEN : 0;
         *     }
         *
         * which is a silent data loss and not a policy. Measured 2026-09-28: an
         * operator frame of 300000 bytes reached the node as 65536 bytes and
         * the remaining 234464 were never sent, with NO close on either socket
         * and nothing in the relay's log. The only symptom is a transfer that
         * stops part way and a session that stays open, which is the exact
         * shape of wstunnel#360 and of the "bytes are accepted and the session
         * does not progress" class this project has been bitten by four times.
         *
         * The premise was also wrong. `maxFrameBytes` bounds ONE FRAME ON THE
         * WIRE, and `ws_write` already honours it by CHUNKING: a 300000-byte
         * write leaves as five frames of at most 65536, each within the limit.
         * Truncating before the write meant the chunker never saw the rest, so
         * the limit was being enforced by the one method that could enforce it
         * correctly, and enforced destructively by the one that could not.
         *
         * So the clamp is gone and `ws_write` is the single place a frame's
         * size is decided. `mf` is kept for the ONE thing it is good for: a
         * node advertising a frame size too small to carry even the id plus
         * one byte cannot be forwarded to at all, and that is worth saying
         * rather than writing a frame the node is guaranteed to reject. */
        unsigned mf = ws_max_frame(&enc->ws);
        if (mf && mf <= RELAY_ID_LEN) {
            /* the node's limit cannot carry a session id plus any payload */
            node_drop(enc);
            if (ns) {
                pthread_mutex_unlock(&ns->wlock);
            }
            client_release(c, 1009, "bad multiplex frame");
            break;
        }
        unsigned char *framed = malloc(n + RELAY_ID_LEN);
        if (framed == NULL) {
            if (ns) {
                pthread_mutex_unlock(&ns->wlock);
            }
            node_drop(enc);
            break;
        }
        memcpy(framed, c->id, RELAY_ID_LEN);
        if (n) {
            memcpy(framed + RELAY_ID_LEN, frame.p, n);
        }
        int wrc = ws_write(&enc->ws, framed, n + RELAY_ID_LEN);
        free(framed);
        if (ns) {
            pthread_mutex_unlock(&ns->wlock);
        }
        node_drop(enc);
        if (wrc != 0) {
            break;
        }
        stat_bytes_out += n;
    }
    buf_free(&frame);
    client_release(c, 0, NULL);
}

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
                /* ⛔ THE TABLE LOCK IS *NOT* HELD ACROSS THE WRITE, AND THAT IS A
                 * DEADLOCK FIX RATHER THAN A STYLE CHOICE.
                 *
                 * The first version held `tlock` while writing `ready` to the
                 * operator's socket, on the reasoning that the pointer must stay
                 * valid. It does not: `ws_write` can block for up to 30 seconds
                 * on a full socket buffer (sock_write's POLLOUT wait), and while
                 * it does, the operator's own connection thread cannot take
                 * `tlock` to publish itself -- so `ready` waited for a client
                 * that was waiting for the lock, and the session hung until the
                 * client's own bound fired.
                 *
                 * ⛔ THE SYMPTOM NAMED THE WRONG THING, WHICH IS WHY IT SURVIVED.
                 * The operator reported "the node never answered `ready`", which
                 * is exactly what a node that is silent looks like, and the node
                 * reported "operator opened session (ready sent)", which is
                 * exactly what a node that answered looks like. Both logs were
                 * correct. Nothing said "a lock was held across a socket write",
                 * because nothing in the protocol knows about locks.
                 *
                 * So the pointer is made safe rather than kept safe: the
                 * session is REFCED under the lock and the write happens
                 * outside it. `ready_seen` is still set BEFORE the write, for
                 * the separate reason that an operator must not see a `ready`
                 * that does not correspond to a session it may use -- and that
                 * ordering needs no lock at all, because the operator's thread
                 * only learns the flag exists by reading the frame. */
                Client *target = NULL;
                pthread_mutex_lock(&tlock);
                {
                    NameSlot *ns = slot_locked(name, 0);
                    if (ns) {
                        for (Client *c = ns->clients; c; c = c->next) {
                            if (id[0] && strcmp(c->id, id) == 0) {
                                /* Authorise BEFORE the byte goes out, so an
                                 * operator that can see the `ready` can also
                                 * send. The write is outside the lock, and
                                 * this assignment is not: the operator's thread
                                 * cannot observe the frame until the write
                                 * below has returned, and the write cannot
                                 * begin until the lock is released. */
                                if (strcmp(verb, "ready") == 0) {
                                    c->ready_seen = 1;
                                }
                                c->refs++;
                                target = c;
                                break;
                            }
                        }
                    }
                }
                pthread_mutex_unlock(&tlock);
                if (target) {
                    ws_write_text(&target->ws, (const unsigned char *)json, n);
                    client_unref(target);
                }
            } else if (strcmp(verb, "close") == 0) {
                /* Same rule as `ready` and the data path: a REFERENCE, not the
                 * table lock, across writes that can block. `ws_close_with`
                 * frees the session's buffers, so this path can free memory
                 * another thread is reading -- which is what client_release's
                 * `ws_released` flag exists for, and why a reference is taken
                 * here too. */
                Client *target = NULL;
                pthread_mutex_lock(&tlock);
                {
                    NameSlot *ns = slot_locked(name, 0);
                    if (ns) {
                        for (Client *c = ns->clients; c; c = c->next) {
                            if (id[0] && strcmp(c->id, id) == 0) {
                                c->refs++;
                                target = c;
                                break;
                            }
                        }
                    }
                }
                pthread_mutex_unlock(&tlock);
                if (target) {
                    char msg[96];
                    snprintf(msg, sizeof msg, "{\"type\":\"close\",\"id\":\"%s\"}", id);
                    ws_write_text(&target->ws, (const unsigned char *)msg, strlen(msg));
                    client_release(target, 1000, "session closed");
                    client_unref(target);
                }
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
        /* ⛔ SAME RULE AGAIN: A REFERENCE ACROSS A BLOCKING WRITE, NOT THE
         * TABLE LOCK. `ws_write` to a slow operator can sit in a 30s POLLOUT
         * wait, and holding `tlock` through that stops the operator's own
         * thread from ever finishing -- the deadlock above, on the data path,
         * where it would have shown up as an ssh that hung under load rather
         * than on every run. */
        Client *target = NULL;
        pthread_mutex_lock(&tlock);
        {
            NameSlot *ns = slot_locked(name, 0);
            if (ns) {
                for (Client *c = ns->clients; c; c = c->next) {
                    if (strcmp(c->id, sid) == 0) {
                        c->refs++;
                        target = c;
                        break;
                    }
                }
            }
        }
        pthread_mutex_unlock(&tlock);
        if (target) {
            /* The operator's advertised frame size, not the node's. */
            size_t payload = n - RELAY_ID_LEN;
            ws_write(&target->ws, frame.p + RELAY_ID_LEN, payload);
            stat_bytes_in += payload;
            client_unref(target);
        }
    }
node_done:
    buf_free(&frame);
    /* ⛔ THE 1011 SWEEP TAKES A REFERENCE PER OPERATOR, AND THE CLOSE HAPPENS
     * OUTSIDE THE TABLE LOCK.
     *
     * The first version did both inside: it took `tlock`, walked
     * `ns->clients`, and called `client_release` on each -- which FREES that
     * operator's websocket buffers -- while an operator's own thread could be
     * in `client_cleanup` dropping its reference and freeing the Client. Two
     * threads, one allocation, and the relay died with
     *
     *     free(): double free detected in tcache 2
     *     Aborted   (the relay process)
     *     Bus error (the node process)
     *
     * ⛔ AND IT TOOK DOWN EVERY SESSION ON THE RELAY, not one, which is the
     * failure mode this file has now produced twice and which is the reason the
     * rule is written out rather than left to the next edit.
     *
     * The rule: a pointer found in a table is not a reference to the object.
     * Take one under the lock, do the work outside it, drop it. `ws_close_with`
     * can block for 30 seconds on a full socket, so holding `tlock` across it
     * is both unsafe and a deadlock. */
    {
        Client *doomed[RELAY_MAX_SESSIONS];
        int ndoomed = 0;
        pthread_mutex_lock(&tlock);
        {
            NameSlot *ns = slot_locked(name, 0);
            if (ns) {
                for (Client *c = ns->clients; c && ndoomed < RELAY_MAX_SESSIONS;
                     c = c->next) {
                    c->refs++;
                    doomed[ndoomed++] = c;
                }
                ns->node = NULL;
                ns->node_dead = 1;
            }
        }
        pthread_mutex_unlock(&tlock);
        for (int i = 0; i < ndoomed; i++) {
            /* ⛔ THE INJECTION POINT FOR U3, AND IT IS *INSIDE* THE LOOP AND
             * AFTER THE REFERENCES ARE TAKEN, WHICH IS THE ONLY PLACE IT MEANS
             * ANYTHING. The defect being guarded is a pointer taken out of the
             * table and used after the operator's own thread is free to have
             * freed it, so the window is between "the sweep holds a pointer"
             * and "the sweep has closed that operator's session". Yielding
             * here is where the operator's thread gets the chance to reach its
             * own last unref. With the reference held, that unref only
             * decrements the count and the object survives; with it removed,
             * the object is freed and the `client_release` below writes through
             * freed memory. */
            relay_fault("sweep-release");
            client_release(doomed[i], 1011, "node disconnected");
            client_unref(doomed[i]);
        }
    }
    ws_close(ws);
}

/* ⛔ `POST /v1/pair` IS THE ANSWER TO ISSUE #13 STEP 1, AND IT IS AN HTTP
 * ENDPOINT ON THIS RELAY RATHER THAN A SUBCOMMAND BECAUSE THE CLIENT THAT
 * CONSUMES IT IS `dropssh pair`, WHICH ALREADY POSTS TO ONE.
 *
 * The protocol is the ajam relay's, measured, and `dropssh_request_pair` in
 * `ws.c` already reads `{name, node_token, connect_token, stop_token,
 * expires}` out of the answer. So the shape was fixed before this was written
 * and writing anything else would have made `dropssh pair` fail against our own
 * relay, which is the definition of the wrong end of the ladder.
 *
 * ⛔ IT REQUIRES A CONFIGURED KEY AND ANSWERS 403 WITHOUT ONE, RATHER THAN
 * ISSUING TOKENS NOBODY CAN VERIFY. A relay that mints pairs but holds no key
 * would hand out two credentials that any relay accepts and that protect
 * nothing, and the operator would believe they had configured something. The
 * refusal names the flag, because "it did not work" is not actionable and
 * "this relay has no key" is the whole answer.
 *
 * ⛔ AND THE NAME IS ECHOED BACK, NOT INVENTED, BUT IT IS VALIDATED FIRST: a
 * name with a path separator or a newline in it is refused, because the name
 * becomes a PATH SEGMENT on both /v1/node/ and /v1/connect/, and a name
 * carrying a separator would let the issuer choose which endpoint the pair is
 * used against. */
static void serve_pair(Transport *t, const char *body) {
    if (!dropssh_key_configured(&relay_key)) {
        refuse(t, 403, "this relay has no token key, so it issues nothing. "
                      "Start it with --token-key or DROPSSH_RELAY_KEY.\n");
        return;
    }
    char name[128] = "";
    /* ⛔ THE RELAY INVENTS THE NAME WHEN THE BODY DOES NOT CARRY ONE, AND THAT
     * IS THE NORMAL CASE RATHER THAN AN ERROR. `dropssh pair` is documented as
     * POSTing `/v1/pair` and printing the name, and it cannot know a name to
     * ask for -- inventing one is the entire point of asking a relay for a
     * pair. Refusing a nameless POST would have made `dropssh pair` fail
     * against our own relay while working against the ajam one, which is the
     * exact half-built shape this whole change exists to avoid.
     *
     * A caller that DOES name it gets that name, which is what makes a pair
     * reproducible across a relay restart and across two relays: re-POSTing the
     * same name against the same key mints the same two tokens. */
    if (body == NULL || json_field(body, "name", name, sizeof name) != 0) {
        char raw[9];
        dropssh_random_b64(raw, sizeof raw, 6);
        snprintf(name, sizeof name, "box-%s", raw);
    }
    if (name[0] == 0) {
        refuse(t, 400, "a pair needs a name\n");
        return;
    }
    if (name[0] == '/' || strchr(name, '/') != NULL || strchr(name, '\\') != NULL ||
        strchr(name, '?') != NULL || strchr(name, '#') != NULL ||
        strchr(name, ' ') != NULL || strchr(name, '\r') != NULL ||
        strchr(name, '\n') != NULL || strchr(name, '|') != NULL) {
        refuse(t, 400, "a node name may not contain a path separator, a "
                       "space, a newline or the token field separator\n");
        return;
    }
    if (strlen(name) >= RELAY_NAME_MAX) {
        refuse(t, 400, "a node name must be shorter than 64 characters\n");
        return;
    }
    char node_tok[600], conn_tok[600];
    long long now = (long long)dropssh_now_ms();
    if (dropssh_token_issue(&relay_key, name, DROPSSH_ROLE_NODE,
                            RELAY_PAIR_TTL, now, node_tok,
                            sizeof node_tok) != 0 ||
        dropssh_token_issue(&relay_key, name, DROPSSH_ROLE_CONNECT,
                            RELAY_PAIR_TTL, now, conn_tok,
                            sizeof conn_tok) != 0) {
        refuse(t, 500, "this relay could not issue a pair\n");
        return;
    }
    long long exp = now + (long long)RELAY_PAIR_TTL * 1000;
    char body_out[2048];
    /* ⛔ THE TWO TOKENS ARE PRINTED ONCE, IN ONE BODY, AND THE BODY IS NOT
     * LOGGED. A relay log is a thing that gets pasted into a bug report, and
     * the two lines above are a node's entire credential. The name, the expiry
     * and the two tokens go to the caller and nowhere else. */
    int bn = snprintf(body_out, sizeof body_out,
        "{\"name\":\"%s\",\"node_token\":\"%s\",\"connect_token\":\"%s\","
        "\"expires\":%lld}\n", name, node_tok, conn_tok, exp);
    if (bn <= 0 || (size_t)bn >= sizeof body_out) {
        refuse(t, 500, "the pair did not fit\n");
        memset(node_tok, 0, sizeof node_tok);
        memset(conn_tok, 0, sizeof conn_tok);
        return;
    }
    char resp[2048 + 256];
    int rn = snprintf(resp, sizeof resp,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", (size_t)bn, body_out);
    if (rn > 0 && (size_t)rn < sizeof resp) {
        t->write(t, resp, (size_t)rn);
    }
    relay_pairs_issued++;
    logf("issued a pair for %s (expires in %us)", name, RELAY_PAIR_TTL);
    /* ⛔ ZEROED AFTER THE WRITE, because this is a long-lived process and a
     * credential left on a stack frame is a credential in a core dump. */
    memset(node_tok, 0, sizeof node_tok);
    memset(conn_tok, 0, sizeof conn_tok);
    memset(body_out, 0, sizeof body_out);
}

/* ⛔ AN UPGRADE IS AUTHENTICATED HERE, AT THE ONE POINT WHERE THE REQUEST HEAD
 * ARE STILL IN HAND, AND NOT AFTER THE 101 HAS GONE OUT.
 *
 * The relay already answers 503 on the UPGRADE for an absent node, precisely so
 * a refusal can be an HTTP status rather than a 101 followed by a Close. A
 * token check placed after the accept would put it back on the wrong side of
 * that split: the peer would have been told "yes" and the only honest answer
 * left would be a Close frame, which an operator's tooling reads as "accepted,
 * then the node hung up" and which this relay's own connect verb once turned
 * into exit 0. So the check runs with the request still un-answered.
 *
 * ⛔ AND IT IS A 403 WITH THE REASON, BECAUSE "NO TOKEN, OR THE WRONG TOKEN" IS
 * NOT AN ANSWER. The four reasons a token is refused are separable and three of
 * them are the operator's to fix: `wrong-role` is the two tokens from one pair
 * being swapped, `expired` is a pair that aged out, and `bad-mac` is a pair from
 * a different relay. Saying which turns a support question into a one-line fix,
 * and the reason is safe to send because it describes the failure and never
 * echoes any part of the credential. */
static int check_token(const char *token, dropssh_role role, const char *name,
                       char *whybuf, size_t whylen) {
    /* An unconfigured relay accepts everything, and says so. */
    if (!dropssh_key_configured(&relay_key)) {
        return 0;
    }
    dropssh_claims c;
    const char *why = "malformed";
    if (dropssh_token_verify(&relay_key, token, role,
                             (long long)dropssh_now_ms(), &c, &why) != 0) {
        relay_tokens_refused++;
        const char *said = NULL;
        if (strcmp(why, "wrong-role") == 0) {
            said = "";
            if (role == DROPSSH_ROLE_NODE) {
                snprintf(whybuf, whylen,
                         "%sthe two tokens from one pair are different: this "
                         "endpoint wants the NODE token, which is the `serve` "
                         "line that `dropssh pair` printed", said);
            } else {
                snprintf(whybuf, whylen,
                         "%sthe two tokens from one pair are different: this "
                         "endpoint wants the CONNECT token, which is the "
                         "`connect` line that `dropssh pair` printed", said);
            }
        } else if (strcmp(why, "expired") == 0) {
            snprintf(whybuf, whylen,
                     "this token expired. Issue a new pair with `dropssh "
                     "pair --relay %s`.", name);
        } else if (strcmp(why, "bad-mac") == 0) {
            snprintf(whybuf, whylen,
                     "this token was not issued by a relay holding this key, "
                     "or it has been altered. It may belong to a different "
                     "relay.");
        } else {
            snprintf(whybuf, whylen, "this token is not a token this relay "
                                     "issued, or it is truncated");
        }
        logf("refused a %s for %s: %s",
             role == DROPSSH_ROLE_NODE ? "node" : "operator", name, why);
        return -1;
    }
    /* ⛔ AND THE NAME IN THE TOKEN MUST MATCH THE NAME IN THE PATH. The token
     * is a bearer credential, so without this a node's token would open a
     * session on ANY name this relay serves -- and the whole point of pairing
     * is that the two halves of a pair are bound to each other. This is the one
     * check that is about what the token SAYS rather than whether it is
     * genuine, and skipping it would make every role separation in this file
     * decorative. */
    if (c.name[0] && strcmp(c.name, name) != 0) {
        relay_tokens_refused++;
        snprintf(whybuf, whylen,
                 "this token is for the name '%s', not for '%s'. A pair is "
                 "two credentials for ONE name, and this one does not match.",
                 c.name, name);
        logf("refused a token for %s that was issued for %s", name, c.name);
        return -1;
    }
    return 0;
}

/* ⛔ THE SOCKS5 LISTENER IS A THIRD DOOR AND IT IS OPTIONAL. A relay without
 * `--socks` never binds it and never reads a SOCKS byte, so the default
 * behaviour and the attack surface of every existing deployment are unchanged.
 *
 * ⛔ IT IS HERE, ON THE OPERATOR, AND NOT IN THE CAGE, AND THAT IS A MEASUREMENT
 * RATHER THAN A PREFERENCE. dropssh#6 re-measured 24/24 that every INET bind is
 * refused with EACCES at uid 0, so a listener in a cage cannot exist at all.
 * ⛔ WHICH CORRECTS sandssh#6's FRAMING, WHICH CALLED THIS A "reverse SOCKS".
 * It is not a reverse SOCKS. A reverse SOCKS would be a listener the CAGE
 * cannot have, and the sentence names a capability that does not exist in the
 * reference cage. */
static char socks_node_name[RELAY_NAME_MAX] = "";
static char socks_host[256] = "";
static int  socks_port = 0;
static int  socks_listen_fd = -1;

/* RFC 1928 reply codes, named. Only the ones this speaks, because a list of
 * numbers a reader has to look up is not a list. */
#define SOCKS_OK                0x00
#define SOCKS_FAIL              0x01
#define SOCKS_RULESET           0x02   /* the answer to "not this node" */
#define SOCKS_HOST_UNREACHABLE  0x04
#define SOCKS_CMD_NOT_SUPPORTED 0x07

static int socks_reply(int fd, unsigned char rep, unsigned char atyp,
                       const void *addr, unsigned char dport) {
    unsigned char buf[262];
    size_t o = 0;
    buf[o++] = 0x05;
    buf[o++] = rep;
    buf[o++] = 0x00;
    buf[o++] = atyp;
    if (atyp == 0x01) {
        memcpy(buf + o, addr, 4);
        o += 4;
    } else if (atyp == 0x03) {
        size_t n = ((const unsigned char *)addr)[0];
        if (n + 1 + 2 > sizeof buf - o) {
            return -1;
        }
        buf[o++] = (unsigned char)n;
        memcpy(buf + o, ((const unsigned char *)addr) + 1, n);
        o += n;
    } else if (atyp == 0x04) {
        memcpy(buf + o, addr, 16);
        o += 16;
    } else {
        return -1;
    }
    buf[o++] = dport;
    return write(fd, buf, o) == (ssize_t)o ? 0 : -1;
}

/* ⛔ EVERY READ IS EXACTLY n BYTES OR IT IS AN ERROR. A short read on a stream
 * is a truncated request, and treating a partial greeting as a complete one is
 * how a SOCKS parser ends up reading a length byte out of nothing. Every
 * length is checked against what actually arrived BEFORE it is used. */
static int read_exact(int fd, void *buf, size_t n, unsigned timeout_ms) {
    unsigned start = dropssh_now_ms();
    size_t got = 0;
    while (got < n) {
        if (dropssh_now_ms() - start > timeout_ms) {
            return -1;
        }
        struct pollfd pf = { .fd = fd, .events = POLLIN };
        int pr = poll(&pf, 1, 100);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (pr == 0) {
            continue;
        }
        ssize_t r = read(fd, ((char *)buf) + got, n - got);
        if (r > 0) {
            got += (size_t)r;
        } else if (r == 0) {
            return -1;
        } else if (errno != EINTR && errno != EAGAIN) {
            return -1;
        }
    }
    return 0;
}

/* ⛔ THE ONE POLICY QUESTION A SOCKS REQUEST CAN ASK, AND THE ANSWER IS ALWAYS
 * "is this exactly the destination the operator named".
 *
 * A SOCKS5 proxy that dials whatever it is asked to dial is an open proxy the
 * moment it is reachable, and this listener is reachable by everything that can
 * reach the operator. So the destination is NOT taken from the request: the
 * operator names it with `--socks`, and a request for anything else is refused
 * with SOCKS `connection not allowed by ruleset` (0x02), which is a code every
 * client already knows how to report.
 *
 * An IPv6 destination is refused rather than compared. A relay that accepted
 * one would have a second, unchecked door, and there is no reason for it to
 * exist before somebody asks for one by name. */
static int socks_destination_allowed(unsigned char atyp,
                                     const unsigned char *addr, unsigned port) {
    if (socks_port <= 0 || port != (unsigned)socks_port) {
        return 0;
    }
    if (atyp == 0x01) {
        struct in_addr want, got;
        if (inet_pton(AF_INET, socks_host, &want) != 1) {
            return 0;
        }
        memcpy(&got, addr, 4);
        return memcmp(&want, &got, 4) == 0;
    }
    if (atyp == 0x03) {
        size_t n = (size_t)addr[0];
        if (n != strlen(socks_host)) {
            return 0;
        }
        for (size_t i = 0; i < n; i++) {
            char a = (char)addr[1 + i];
            char b = socks_host[i];
            if (a >= 'A' && a <= 'Z') { a = (char)(a + 32); }
            if (b >= 'A' && b <= 'Z') { b = (char)(b + 32); }
            if (a != b) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

/* ⛔ A SOCKS REQUEST IS SERVED BY THE ORDINARY OPERATOR PATH, AND THE WHOLE OF
 * THIS FUNCTION IS BUILDING A Client. There is no private forwarding loop here
 * and no second reader on a node's socket, which is the property that makes
 * this safe to add: bytes reach a node exactly one way in this file.
 *
 * The sequence is RFC 1928's, and every field is bounded before it is read:
 * greeting (VER NMETHODS METHODS), then request (VER CMD RSV ATYP ADDR PORT). */
/* The SOCKS client's socket and the socketpair end its bytes go into. The pump
 * is a poll over both: readable client -> write into the socketpair, readable
 * socketpair -> write to the client. `client_thread` owns the OTHER end of the
 * socketpair and is the only reader of it, so a frame's header and payload
 * always leave the relay together. */
struct socks_ctx {
    int cfd;         /* the SOCKS client */
    int pair;        /* the socketpair end the relay reads and writes */
};

static void socks_pump(struct socks_ctx *s) {
    unsigned char buf[32768];
    struct pollfd pf[2];
    pf[0].fd = s->cfd;  pf[0].events = POLLIN;
    pf[1].fd = s->pair; pf[1].events = POLLIN;
    for (;;) {
        pf[0].revents = 0;
        pf[1].revents = 0;
        int pr = poll(pf, 2, 1000);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (pr == 0) {
            continue;
        }
        if (pf[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = read(s->cfd, buf, sizeof buf);
            if (n > 0) {
                size_t off = 0;
                while (off < (size_t)n) {
                    ssize_t w = write(s->pair, buf + off, (size_t)n - off);
                    if (w > 0) {
                        off += (size_t)w;
                    } else if (w < 0 && errno == EINTR) {
                        continue;
                    } else {
                        return;
                    }
                }
            } else if (n == 0) {
                /* ⛔ THE CLIENT HALF-CLOSED, AND THE FAR END IS TOLD SO RATHER
                 * THAN THE CONNECTION SIMPLY ENDING. A SOCKS client that sends
                 * a request and half-closes is normal -- HTTP over a SOCKS
                 * proxy does it -- and the response still has to come back. */
                shutdown(s->pair, SHUT_WR);
                pf[0].events = 0;      /* stop polling it; only the far side now */
            } else if (errno != EINTR && errno != EAGAIN) {
                return;
            }
        }
        if (pf[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = read(s->pair, buf, sizeof buf);
            if (n > 0) {
                size_t off = 0;
                while (off < (size_t)n) {
                    ssize_t w = write(s->cfd, buf + off, (size_t)n - off);
                    if (w > 0) {
                        off += (size_t)w;
                    } else if (w < 0 && errno == EINTR) {
                        continue;
                    } else {
                        return;
                    }
                }
            } else if (n == 0) {
                return;
            } else if (errno != EINTR && errno != EAGAIN) {
                return;
            }
        }
    }
}

static void *socks_thread(void *arg) {
    int fd = (int)(intptr_t)arg;
    unsigned char head[2];
    if (read_exact(fd, head, 2, 10000) != 0 || head[0] != 0x05) {
        close(fd);
        return NULL;
    }
    unsigned char methods[255];
    if (head[1] == 0 || head[1] > sizeof methods) {
        close(fd);
        return NULL;
    }
    if (read_exact(fd, methods, head[1], 10000) != 0) {
        close(fd);
        return NULL;
    }
    int noauth = 0;
    for (unsigned i = 0; i < head[1]; i++) {
        if (methods[i] == 0x00) {
            noauth = 1;
        }
    }
    /* ⛔ NOAUTH IS ALL THAT IS OFFERED, AND 0xFF IS HOW A SERVER SAYS "NONE OF
     * YOUR METHODS". A relay that accepted a username and password it never
     * checked would be worse than one that refuses, and refusing is what a
     * client can act on. */
    unsigned char sel[2] = { 0x05, noauth ? 0x00 : 0xff };
    if (write(fd, sel, 2) != 2 || !noauth) {
        close(fd);
        return NULL;
    }
    unsigned char req[4];
    if (read_exact(fd, req, 4, 10000) != 0 || req[0] != 0x05) {
        close(fd);
        return NULL;
    }
    unsigned char atyp = req[3];
    unsigned char addr[256];
    size_t alen;
    if (atyp == 0x01) {
        alen = 4;
    } else if (atyp == 0x03) {
        if (read_exact(fd, addr, 1, 10000) != 0) {
            close(fd);
            return NULL;
        }
        alen = (size_t)addr[0] + 1;
        if (alen > sizeof addr) {
            close(fd);
            return NULL;
        }
        if (alen > 1 && read_exact(fd, addr + 1, alen - 1, 10000) != 0) {
            close(fd);
            return NULL;
        }
    } else if (atyp == 0x04) {
        alen = 16;
    } else {
        /* ⛔ AN UNKNOWN ADDRESS TYPE IS REFUSED, NOT ASSUMED. RFC 1928 defines
         * three; a fourth is a client speaking something else, and guessing its
         * length is how a parser reads past the request. */
        close(fd);
        return NULL;
    }
    unsigned char dport[2];
    if (read_exact(fd, dport, 2, 10000) != 0) {
        close(fd);
        return NULL;
    }
    unsigned port = ((unsigned)dport[0] << 8) | dport[1];

    if (req[1] != 0x01) {
        /* BIND and UDP ASSOCIATE are refused rather than half-implemented: a
         * reply a client believes is a promise this relay does not keep. */
        logf("socks: refused command %u; only CONNECT is served", req[1]);
        socks_reply(fd, SOCKS_CMD_NOT_SUPPORTED, atyp, addr, dport[1]);
        close(fd);
        return NULL;
    }
    if (!socks_destination_allowed(atyp, addr, port)) {
        logf("socks: refused a destination that is not the one --socks named");
        socks_reply(fd, SOCKS_RULESET, atyp, addr, dport[1]);
        close(fd);
        return NULL;
    }

    /* The node must be connected, or the client is told so rather than being
     * given a CONNECT that succeeds and then delivers nothing. */
    pthread_mutex_lock(&tlock);
    NameSlot *ns = slot_locked(socks_node_name, 0);
    int have_node = (ns != NULL && ns->node != NULL);
    pthread_mutex_unlock(&tlock);
    if (!have_node) {
        logf("socks: no node is connected as %s", socks_node_name);
        socks_reply(fd, SOCKS_HOST_UNREACHABLE, atyp, addr, dport[1]);
        close(fd);
        return NULL;
    }

    /* The socketpair is the Client's "websocket": the far end is the thread
     * that pumps the SOCKS client's bytes, and `client_thread` sees an
     * ordinary operator from here on. This is the same shape the node's
     * socketpair uses for dropbear, and it is why no forwarding loop is
     * needed. */
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        socks_reply(fd, SOCKS_FAIL, atyp, addr, dport[1]);
        close(fd);
        return NULL;
    }
    if (socks_reply(fd, SOCKS_OK, atyp, addr, dport[1]) != 0) {
        close(pair[0]);
        close(pair[1]);
        close(fd);
        return NULL;
    }
    logf("socks: forwarding a connection to %s:%u through node %s",
         socks_host, port, socks_node_name);

    /* A WsSession over the socketpair's relay end. `ws_client` owns the
     * transport and the buffers, and `ws_move` below hands it to the Client,
     * so the session has exactly one owner for its whole life -- which is U2,
     * enforced by construction rather than by a rule somebody has to remember. */
    Transport *t = transport_from_fd(pair[0], "socks");
    if (t == NULL) {
        close(pair[0]);
        close(pair[1]);
        close(fd);
        return NULL;
    }
    WsSession ws;
    ws_status st;
    memset(&st, 0, sizeof st);
    /* The socketpair is already a byte pipe; there is no upgrade to accept, so
     * the session is initialised directly rather than through a handshake. */
    memset(&ws, 0, sizeof ws);
    ws.t = t;
    ws.is_client = 1;
    ws.keepalive_ms = 0;          /* a SOCKS connection is not keepalived here */
    ws.fq_cap = WS_DEFAULT_QUEUE_BYTES;
    ws.max_frame = WS_HELLO_DEFAULT_FRAME;
    ws.max_sessions = WS_HELLO_DEFAULT_SESSIONS;
    buf_init(&ws.rbuf);
    buf_init(&ws.frag);
    buf_init(&ws.spill);

    Client *c = calloc(1, sizeof *c);
    if (c == NULL) {
        buf_free(&ws.rbuf);
        buf_free(&ws.frag);
        buf_free(&ws.spill);
        t->close(t);
        close(pair[1]);
        close(fd);
        return NULL;
    }
    c->fd = pair[0];
    c->refs = 1;
    c->socks_fd = fd;
    c->socks_done = 1;
    ws_move(&c->ws, &ws);
    snprintf(c->name, sizeof c->name, "%s", socks_node_name);
    random_id(c->id);
    pthread_mutex_lock(&tlock);
    ns = slot_locked(socks_node_name, 0);
    c->next = ns->clients;
    ns->clients = c;
    ns->client_count++;
    session_count++;
    stat_sessions_opened++;
    peer_count++;
    if (peer_count > stat_peak_peers) {
        stat_peak_peers = peer_count;
    }
    /* ⛔ THE NODE IS TOLD IMMEDIATELY, WITH THE DESTINATION IN THE `open`, AND
     * NOT WITH A 32-BYTE PREFIX ON EVERY DATA FRAME.
     *
     * This is the shape dropssh#10 records as structurally better than ours
     * and names as not adoptable, because the 32-hex prefix is the AJAM
     * RELAY's rule and a node that deviates is closed 1009. Here there is no
     * ajam relay involved: both ends are ours, so the destination is announced
     * once, at setup, in the `open` this relay already writes. There is no
     * per-frame field to forget, and forgetting one is what produced close
     * 1009 "bad multiplex frame" in the first place.
     *
     * The consequence, stated rather than discovered later: a SOCKS forward
     * works against a `dropssh serve` node and NOT against an ajam node, and
     * that is in the option's help. */
    {
        NodeCtx *enc = node_hold_locked(ns);
        if (ns) {
            pthread_mutex_lock(&ns->wlock);
        }
        char open_msg[512];
        int on = snprintf(open_msg, sizeof open_msg,
                          "{\"type\":\"open\",\"id\":\"%s\",\"host\":\"%s\","
                          "\"port\":%u,\"mode\":\"socks\"}",
                          c->id, socks_host, port);
        int wrote = (enc != NULL && on > 0 && (size_t)on < sizeof open_msg) &&
                    ws_write_text(&enc->ws, (const unsigned char *)open_msg,
                                  (size_t)on) == 0;
        if (ns) {
            pthread_mutex_unlock(&ns->wlock);
        }
        if (enc) {
            node_drop(enc);
        }
        if (!wrote) {
            client_release(c, 1011, "the node disconnected");
        }
    }
    pthread_mutex_unlock(&tlock);

    if (!c->ws_released) {
        /* ⛔ THE SOCKS CLIENT'S BYTES ARE PUMPED ON THE SOCKETPAIR, AND THE
         * PUMP IS A POLL WITH NO BUSY WAIT. This is the only place the SOCKS
         * socket is read, and it runs in THIS thread, so `client_thread` below
         * remains the only reader of the Client's websocket. Two readers on one
         * session is the defect this file has already produced once. */
        struct socks_ctx sc = { .cfd = c->socks_fd, .pair = pair[1] };
        socks_pump(&sc);
    }
    /* The SOCKS client's socket belongs to this thread, not to the Client, so
     * it is closed here and not by client_release. */
    if (c->socks_fd >= 0) {
        close(c->socks_fd);
        c->socks_fd = -1;
    }

    pthread_mutex_lock(&tlock);
    ns = slot_locked(socks_node_name, 0);
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
    client_unref(c);
    close(pair[1]);
    return NULL;
}

/* The SOCKS accept loop. It owns `socks_listen_fd` for the life of the relay
 * and hands each connection to a detached thread, exactly as the websocket
 * listener does. */
static void *socks_accept_thread(void *unused) {
    (void)unused;
    while (socks_listen_fd >= 0) {
        int sfd = accept(socks_listen_fd, NULL, NULL);
        if (sfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            logf("socks accept: %s", strerror(errno));
            dropssh_sleep_ms(100);
            continue;
        }
        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &attr, socks_thread,
                           (void *)(intptr_t)sfd) != 0) {
            close(sfd);
        }
        pthread_attr_destroy(&attr);
    }
    return NULL;
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
    char token_hdr[1024] = "";
    char why[320] = "";
    /* ⛔ ONE READER FOR BOTH DOORS, AND THE PAIR DOOR IS THE UPGRADE READER
     * REFUSING ITS INPUT RATHER THAN A SECOND READ.
     *
     * `ws_server_peek` reads the whole request (headers + body) into `rbuf`,
     * parses the target, and returns -1 when there is no `Sec-WebSocket-Key` --
     * which is exactly what a plain `POST /v1/pair` looks like. At that point
     * `rbuf` still holds the entire request, because the buffer is only reset
     * once the key is found. So the body of a pair request is already in hand
     * and a second read would be a second parse of a stream that cannot be
     * rewound.
     *
     * The first version peeked four bytes to choose the door and could not
     * un-consume them, which on a stream loses the start of a GET upgrade. The
     * lesson is the one this file keeps making: read once, and let the reader
     * that already has the bytes decide.
     */
    if (ws_server_peek_tok(t, &ws, path, sizeof path, token_hdr,
                           sizeof token_hdr, &st) != 0) {
        /* No WebSocket key. Either it was a pair POST, or it was junk. The
         * request is still in rbuf, so the pair handler can read it. */
        int is_pair = 0;
        if (ws.rbuf.p != NULL && ws.rbuf.len > 0) {
            if ((ws.rbuf.len >= 5 && memcmp(ws.rbuf.p, "POST ", 5) == 0) ||
                (ws.rbuf.len >= 4 && memcmp(ws.rbuf.p, "POST", 4) == 0)) {
                is_pair = 1;
            }
        }
        if (is_pair) {
            /* the body is everything after the header block, and the target is
             * the second word of the request line */
            char req_path[512] = "";
            {
                const char *sp = (const char *)memchr(ws.rbuf.p, ' ', ws.rbuf.len);
                if (sp != NULL) {
                    const char *sp2 = (const char *)memchr(sp + 1, ' ',
                                             ws.rbuf.len - (size_t)(sp + 1 - (const char *)ws.rbuf.p));
                    if (sp2 != NULL) {
                        size_t n = (size_t)(sp2 - sp - 1);
                        if (n >= sizeof req_path) { n = sizeof req_path - 1; }
                        memcpy(req_path, sp + 1, n);
                        req_path[n] = 0;
                    }
                }
            }
            unsigned char *brk = memmem(ws.rbuf.p, ws.rbuf.len, "\r\n\r\n", 4);
            char body[2048] = "";
            if (brk != NULL) {
                size_t hlen = (size_t)(brk - ws.rbuf.p) + 4;
                size_t bl = ws.rbuf.len - hlen;
                if (bl >= sizeof body) { bl = sizeof body - 1; }
                memcpy(body, ws.rbuf.p + hlen, bl);
                body[bl] = 0;
            }
            /* ⛔ THE RESPONSE GOES OUT BEFORE ANY CLOSE, IN THIS ORDER, AND
             * REVERSING THEM IS A SILENT FAILURE RATHER THAN A CRASH.
             *
             * `ws_close` sends a WebSocket Close frame and then shuts the
             * transport. This request is plain HTTP and the peer is reading an
             * HTTP response. The first version closed first, so the peer
             * received `\x88\x00` -- a WebSocket close -- and then nothing: the
             * answer had been written to a socket that was already shut. The
             * relay stayed alive, it logged nothing, and the symptom was a
             * two-byte reply to every single pair request.
             *
             * A peer that sent a POST and received a WebSocket Close has told
             * this relay it is not a WebSocket peer, and the right answer to
             * that is an HTTP status, not a frame from a protocol the peer did
             * not ask for. */
            if (strcmp(req_path, "/v1/pair") == 0) {
                serve_pair(t, body);
            } else {
                refuse(t, 404, "this relay serves POST /v1/pair, GET "
                               "/v1/node/<name> and GET /v1/connect/<name>\n");
            }
            memset(body, 0, sizeof body);
            /* The transport is shut by the transport's own owner below; the
             * WsSession here never had a 101 sent, so it has nothing of its
             * own to close. */
            buf_free(&ws.rbuf);
            return NULL;
        }
        stat_handshakes_refused++;
        logf("upgrade refused: %s", ws_strerror(&st));
        ws_close(&ws);
        return NULL;
    }
    if (strcmp(path, "/v1/pair") == 0) {
        refuse(t, 400, "/v1/pair is a POST, not a GET\n");
        ws_close(&ws);
        return NULL;
    }
    if (strcmp(path, "/v1/pair") == 0) {
        refuse(t, 400, "/v1/pair is a POST, not a GET\n");
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
        refuse(t, 404, "unknown path: this relay serves /v1/node/<name>, "
                      "/v1/connect/<name> and POST /v1/pair\n");
        ws_close(&ws);
        return NULL;
    }
    /* ⛔ THE TOKEN IS CHECKED HERE, ON THE UPGRADE, WITH THE 101 NOT YET SENT.
     * Everything about where this sits was argued at check_token: a check after
     * the accept leaves only a Close frame to answer with, and a client reads
     * that as "accepted, then the node hung up". A refusal here is an HTTP
     * status, which is what an operator's tooling can act on.
     *
     * A peer that sent NO token at all is refused with the same 403 and a
     * reason that says so, rather than being let through: a relay that has a
     * key has been told to check, and "check" that accepts an absent token is
     * how an unauthenticated path gets shipped by accident. */
    if (dropssh_key_configured(&relay_key) && token_hdr[0] == 0) {
        /* ⛔ GATED ON THE KEY BEING CONFIGURED, WHICH LOOKS REDUNDANT BECAUSE
         * `check_token` ALSO RETURNS EARLY WHEN IT IS NOT, AND IT IS NOT.
         *
         * The first version refused an absent token before asking `check_token`
         * anything, so a relay with NO key -- which is every relay anyone has
         * run until this change -- refused every peer with "no token was sent"
         * while its own banner said "ACCEPTED as anything". The banner and the
         * behaviour were two different claims about the same process, and the
         * gate that broke the existing suites was this line.
         *
         * The order that is correct is: ask whether this relay verifies at all,
         * and only then decide what an absent token means. An unconfigured
         * relay has no opinion about tokens, so an absent one is not a fault. */
        stat_handshakes_refused++;
        relay_tokens_refused++;
        snprintf(why, sizeof why,
                 "no token was sent. This relay is configured with a token "
                 "key, so every peer must present the token `dropssh pair` "
                 "printed for its role.");
        logf("refused a %s for %s: no token",
             is_node ? "node" : "operator", name);
        refuse(t, 403, why);
        ws_close(&ws);
        return NULL;
    }
    if (check_token(token_hdr, is_node ? DROPSSH_ROLE_NODE : DROPSSH_ROLE_CONNECT,
                    name, why, sizeof why) != 0) {
        stat_handshakes_refused++;
        refuse(t, 403, why);
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
        /* ⛔ THE NODE'S SESSION IS HEAP-ALLOCATED AND IT IS PUBLISHED AS A
         * POINTER TO THE CONTEXT, NOT A POINTER INTO IT.
         *
         * The old version kept a WsSession on the accepting thread's STACK and
         * put that pointer in a global table, which is a use-after-return that
         * works with one connection and is a crash with two. The heap version
         * fixed that but introduced the mirror-image bug: `&nc->ws` outlived
         * nothing, because `free(nc)` ran while a reader held the pointer. The
         * table holds `nc` and readers hold a reference on it, so neither the
         * stack's lifetime nor a bare interior pointer can be the owner. */
        NodeCtx *nc = calloc(1, sizeof *nc);
        if (nc == NULL) {
            pthread_mutex_unlock(&tlock);
            refuse(t, 503, "out of memory\n");
            ws_close(&ws);
            return NULL;
        }
        /* Moved, not copied, for the same reason as the operator's session
         * below: a struct copy shares its buffer POINTERS, so the stack `ws`
         * and `nc->ws` would own the same allocations and the first close
         * would free memory the other still points at. The node's session is
         * closed by exactly one thread -- its own -- and `ws_move` leaves the
         * stack copy inert, so every other `ws_close(&ws)` on this path is a
         * no-op rather than a second free. `docs/relay-issues.md` U2. */
        ws_move(&nc->ws, &ws);
        nc->fd = fd;
        snprintf(nc->name, sizeof nc->name, "%s", name);
        /* The table's own reference on the node, dropped by node_drop when
         * this connection thread returns. Readers add one for the duration of
         * a write that can block. Same contract as `Client.refs`. */
        nc->refs = 1;
        e->node = nc;
        e->node_dead = 0;
        peer_count++;
        if (peer_count > stat_peak_peers) {
            stat_peak_peers = peer_count;
        }
        pthread_mutex_unlock(&tlock);
        logf("node %s connected (peers %u)", name, peer_count);

        /* The node owns its socket for the rest of the connection, and this
         * thread is the one that blocks in node_thread for exactly that long.
         *
         * ⛔ BUT "OUTLIVES EVERY USE OF IT" WAS TRUE OF THE NODE'S OWN USES AND
         * FALSE OF AN OPERATOR'S, and that was a use-after-free. An operator
         * reads `ns->node`, releases `tlock`, and then writes to the node; the
         * outgoing node's own thread took no lock an operator holds and went
         * straight to `free(nc)`. So the context is now freed through the
         * same refcount the readers use: the reference taken when it was
         * published is dropped here, and if an operator still holds one the
         * free happens on that operator's thread instead. */
        node_thread(nc);
        pthread_mutex_lock(&tlock);
        peer_count--;
        NameSlot *fin = slot_locked(name, 0);
        if (fin && fin->node == nc) {
            fin->node = NULL;
            fin->node_dead = 1;
        }
        pthread_mutex_unlock(&tlock);
        logf("node %s disconnected (peers %u)", name, peer_count);
        node_drop(nc);
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
    /* The table's own reference, dropped in client_cleanup. */
    c->refs = 1;
    /* ⛔ THE SESSION IS MOVED, NOT COPIED, AND THAT IS THE THIRD VERSION OF
     * THIS LINE.
     *
     * The first version did `memcpy(&c->ws, &ws, sizeof ws)`, which copies the
     * struct -- and the struct's buffers are POINTERS. So the stack `ws` and
     * `c->ws` then own the same four allocations, and closing either one frees
     * memory the other still points at. Every refusal path further down this
     * function closes the stack `ws`, the session is also closed by the node's
     * 1011 sweep or by client_thread, and the relay dies with
     *
     *     free(): double free detected in tcache 2
     *
     * ⛔ WHICH IS THE THIRD DOUBLE FREE THIS FILE HAS PRODUCED AND THE THIRD
     * TIME THE SYMPTOM NAMED SOMETHING ELSE. The first was two threads closing
     * one session; the second was freeing a Client out from under a thread
     * walking the list; this one is an ALIASED OWNER. All three are the same
     * mistake -- two names for an object read as two objects -- and all three
     * took the whole relay down rather than one session, which is why the rule
     * is written out here.
     *
     * The move is by hand rather than `*c->ws = ws` because that is a copy and
     * a copy is what is being removed. It is now `ws_move(&c->ws, &ws)`, a
     * single named operation that clears the source ITSELF, so every
     * `ws_close(&ws)` on the refusal paths is a no-op on an already-moved
     * session rather than a second free -- and, unlike the hand-written
     * `c->ws = ws; memset(&ws, 0, ...)` pair it replaced, the clearing is not a
     * separate statement a future edit can delete.
     *
     * ⛔ AND WHY THE MOVE IS DEFENCE IN DEPTH RATHER THAN A FIX FOR AN OBSERVED
     * CRASH, WHICH IS NOT THE CLAIM AN EARLIER DRAFT OF THIS COMMENT MADE.
     * Reverting it to a `memcpy` and running `tests/mux-probe.py` 20 times
     * produced no crash, and reading the function now shows why: on the
     * operator's path every `ws_close(&ws)` -- the peer-cap, full, name, OOM,
     * no-node and session-limit refusals -- is at or ABOVE this line, so no
     * close of the stack copy runs after the Client owns the buffers. The two
     * names never both close the same allocation on the current control flow.
     *
     * So the aliasing is not the cause of the `double free detected in tcache 2`
     * that this line's comment originally claimed. That was the 1011 sweep
     * closing an operator's session with no reference held, which is fixed and
     * is a real fix. The move is kept because the property it establishes --
     * one owner per session, established where the session is stored -- is the
     * property every one of the three double frees in this file needed and none
     * of them had, and because a future refusal added BELOW this line would
     * reintroduce the aliasing silently. That is a change to make the next
     * edit's failure mode loud, not a fix for a crash measured today.
     *
     * ⛔ U2 IS NOW CLOSED BY `ws_move`, and the guard for it is a case that
     * drives a refusal BELOW this line -- the `if (!open_ok)` block, which is
     * the only path in this function that runs after the move and closes the
     * session. See `tests/mux-probe.py` case 9. */
    ws_move(&c->ws, &ws);
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
     * the node's websocket from an operator's thread.
     *
     * ⛔ AND THE NODE IS HELD ACROSS IT. This is the ONE write in this file
     * that happens BELOW the `c->ws` move, which is what makes it the case
     * U2 needs: with the session copied rather than moved, a refusal here
     * would close a stack copy that the Client also owns. The reference is
     * what makes the node's context outlive the write, for the same reason the
     * data path holds one -- see node_hold. */
    NameSlot *ns;
    NodeCtx  *enc;
    pthread_mutex_lock(&tlock);
    ns = slot_locked(name, 0);
    enc = node_hold_locked(ns);
    if (ns) {
        pthread_mutex_lock(&ns->wlock);
    }
    pthread_mutex_unlock(&tlock);
    int open_ok = 0;
    if (enc != NULL) {
        open_ok = ws_write_text(&enc->ws, (const unsigned char *)open_msg,
                                strlen(open_msg)) == 0;
    }
    if (ns) {
        pthread_mutex_unlock(&ns->wlock);
    }
    if (enc) {
        node_drop(enc);
    }
    if (!open_ok) {
        client_release(c, 1011, "the node disconnected");
        goto client_cleanup;
    }

    /* The operator's thread owns its own socket, and the table entry is
     * removed after it exits, so a late node frame for a dead id is dropped
     * rather than written to a closed websocket. `c` is heap and owns its own
     * name, so nothing read here can dangle when this thread returns. */
    client_thread(c);

client_cleanup:
    /* ⛔ THE TABLE'S REFERENCE IS DROPPED, AND THE FREE HAPPENS ONLY IF THAT WAS
     * THE LAST ONE -- AND NOT UNDER THE LOCK.
     *
     * Three versions of this line have been wrong in three different ways, and
     * each was found by running the relay rather than by reading it:
     *
     *   1. `free(c)` after the unlock. The client is out of the list but still
     *      reachable by a thread walking it, and the node's 1011 sweep does
     *      exactly that. Heap corruption, about 1 run in 20.
     *   2. `free(c)` under the lock. Correct against that race, and wrong the
     *      other way: a free under a lock another thread takes turns a
     *      use-after-free into a lock-order inversion, and a Client another
     *      thread holds a REFERENCE to is freed while it is being used.
     *   3. this: decrement under the lock, free outside it, and only when the
     *      count reaches zero. Both races are then covered by one mechanism
     *      rather than by two rules that have to agree.
     *
     * The refcount is not a nicety here. Every path that takes a Client out of
     * the table and then does something that can block -- and a socket write can
     * block for 30 seconds -- holds a reference across the gap, and this is
     * where the table's own reference goes. */
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

    /* ⛔ THE OTHER END OF U3'S WINDOW. The operator's own thread is about to
     * drop the table's last reference, which is the free when nothing else
     * holds one. Yielding between the unlink and the unref gives the node's
     * sweep the same chance to be inside `client_release` on this Client. The
     * two points are symmetric on purpose: either one alone would be a guess
     * about which thread wins, and a guard built on a guess is the disease
     * this file exists to correct. */
    relay_fault("client-last-unref");

    client_unref(c);

    logf("operator for %s detached (peers %u)", name, peer_count);
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
    /* ⛔ AND IT SAYS WHETHER IT IS CHECKING TOKENS, BECAUSE "WHETHER THIS RELAY
     * ENFORCES ANYTHING" IS THE FIRST QUESTION AND TODAY IT HAS NO ANSWER. The
     * line is the whole answer in one word, and it is deliberately not the
     * absence of a line. */
    printf("token_key %s\n", dropssh_key_configured(&relay_key)
           ? "configured" : "unset (every token is accepted)");
    printf("pairs_issued %llu\n", relay_pairs_issued);
    printf("tokens_refused %llu\n", relay_tokens_refused);
    printf("pair_ttl_s %u\n", RELAY_PAIR_TTL);
    /* ⛔ THE TWO LIVENESS COUNTERS (#10 adopt 1 and 2) ARE COUNTED PER SESSION
     * AND SUMMED HERE, because a policy number nobody can read is a policy
     * number nobody can argue with. `pings_in_flight` is a LIVE value summed
     * over every session this relay holds, so a non-zero number on an idle
     * relay is a relay whose peers have stopped answering. */
    {
        unsigned pings = 0, drops = 0;
        for (int i = 0; i < RELAY_MAX_NAMES; i++) {
            if (!table[i].used) {
                continue;
            }
            if (table[i].node) {
                pings += ws_pings_in_flight(table[i].node);
            }
            for (Client *c = table[i].clients; c; c = c->next) {
                pings += ws_pings_in_flight(&c->ws);
                drops += ws_control_drops(&c->ws);
            }
        }
        printf("pings_in_flight %u\n", pings);
        printf("control_dropped %u\n", drops);
    }
    fflush(stdout);
}

int dropssh_relay_main(int argc, char **argv) {
    const char *listen_path = NULL;
    int status_mode = 0;
    /* ⛔ THE FAULT-INJECTION POINT IS VALIDATED, NOT MERELY READ. An
     * unrecognised value is refused, because a silently-ignored typo would
     * leave the instrument disabled and the U3 case green for the wrong
     * reason -- the same failure as the U1 probe's help-text parse, which
     * matched nothing and fell back to a number that happened to be right. */
    {
        const char *fault = getenv("DROPSSH_RELAY_FAULT");
        if (fault && fault[0]) {
            if (strcmp(fault, "sweep-release") == 0 ||
                strcmp(fault, "client-last-unref") == 0) {
                relay_fault_point = fault;
            } else {
                fprintf(stderr,
                        "dropssh relay: DROPSSH_RELAY_FAULT is '%s', which is not "
                        "a known injection point. The points are 'sweep-release' "
                        "and 'client-last-unref'. Refusing rather than ignoring "
                        "it, so a typo cannot silently disable the "
                        "instrument.\n", fault);
                return 2;
            }
        }
    }
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
        } else if (strcmp(argv[i], "--socks") == 0 && i + 1 < argc) {
            socks_listen_arg = argv[++i];
        } else if (strcmp(argv[i], "--socks-dest") == 0 && i + 1 < argc) {
            socks_dest_arg = argv[++i];
        } else if (strcmp(argv[i], "--socks-node") == 0 && i + 1 < argc) {
            socks_node_arg = argv[++i];
        } else if (strcmp(argv[i], "--token-key") == 0 && i + 1 < argc) {
            token_key_arg = argv[++i];
        } else if (strcmp(argv[i], "--pair-ttl") == 0 && i + 1 < argc) {
            /* ⛔ PARSED WITH strtol AND THE END POINTER CHECKED, for the reason
             * review 1 found for `--bound-ms`: `atoi`'s answer to a non-numeric
             * string is 0, and 0 here would mean a pair that expires the
             * instant it is issued. A flag whose invalid input silently
             * produces the worst value is worse than one that refuses. */
            {
                char *end = NULL;
                long v = strtol(argv[++i], &end, 10);
                if (end == argv[i] || (end && *end) || v <= 0 || v > 31536000L) {
                    fprintf(stderr, "dropssh relay: --pair-ttl wants a number of "
                            "seconds in 1..31536000. '%s' is not one.\n",
                            argv[i]);
                    return 2;
                }
                RELAY_PAIR_TTL = (unsigned)v;
            }
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
"  --token-key PASSPHRASE       verify peers' tokens, and serve POST /v1/pair.\n"
"                              Without it this relay accepts every token and\n"
"                              issues nothing, which is what it has always\n"
"                              done. DROPSSH_RELAY_KEY does the same.\n"
"  --pair-ttl SECONDS           how long an issued pair is good for (86400)\n"
"\n"
"SOCKS5, on the OPERATOR and never in the cage\n"
"  --socks HOST:PORT           serve a SOCKS5 listener here. The listener is on\n"
"                              this machine because a cage cannot bind INET at\n"
"                              all (dropssh#6, measured 24/24), which is also\n"
"                              why this is not a 'reverse SOCKS'\n"
"  --socks-node NAME           reach the destination through this node\n"
"  --socks-dest HOST:PORT      and only this destination. A client asking for\n"
"                              anything else is refused with SOCKS 0x02, and\n"
"                              omitting this option is refused at startup: a\n"
"                              SOCKS5 proxy that dials what it is asked to\n"
"                              dial is an open proxy\n"
"\n"
"                              A restart forgets the forwards, deliberately\n"
"                              (wiretap's README:481 says the same and this is\n"
"                              the right shape for a single-tenant relay). A\n"
"                              forward works against a `dropssh serve` node and\n"
"                              NOT against an ajam one: the destination is sent\n"
"                              once in the `open`, which the ajam protocol has\n"
"                              no field for.\n"
"  --status                     print what this process is doing, and exit\n"
"\n"
"TESTING\n"
"  DROPSSH_RELAY_FAULT=sweep-release|client-last-unref\n"
"                             yield at that point in the 1011 sweep or in an\n"
"                             operator's last unref. Inert unless set, and an\n"
"                             unrecognised value is refused rather than\n"
"                             ignored. It is an instrument for the race the\n"
"                             sweep has twice crashed on, NOT the reason U3 was\n"
"                             closed: the case that closed U3 reaches the race\n"
"                             without it. See docs/relay-issues.md.\n"
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
    /* ⛔ THE KEY IS APPLIED BEFORE `--status` IS ANSWERED, because `--status` has
     * to be able to say whether this process verifies or accepts everything, and
     * a `--status` that ran first would always answer about an unconfigured
     * relay no matter what the environment said. */
    {
        const char *k = token_key_arg;
        if (k == NULL) {
            k = getenv("DROPSSH_RELAY_KEY");
        }
        dropssh_key_from_passphrase(&relay_key, k);
        if (k != NULL && !dropssh_key_configured(&relay_key)) {
            /* ⛔ A KEY THAT DID NOT LOAD IS FATAL RATHER THAN "UNSET", because
             * the only way `dropssh_key_from_passphrase` leaves the key
             * unconfigured given a non-empty passphrase is a build with no
             * SHA-256, and continuing would mean a relay that was told to
             * verify and does not. */
            fprintf(stderr, "dropssh relay: a token key was given but this "
                    "build could not hash it, so this relay cannot verify "
                    "anything. Refusing to start rather than accepting "
                    "every peer.\n");
            return 2;
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
        /* ⛔ AND THE SECOND BANNER LINE SAYS WHETHER TOKENS ARE CHECKED. A relay
         * that accepts every peer while an operator believes it is enforcing
         * role separation is the worst of the two available states, and the
         * only thing that prevents it is saying so here rather than leaving
         * the operator to infer it from a refusal that never comes. */
        logf("tokens: %s", dropssh_key_configured(&relay_key)
             ? "VERIFIED against this relay's key, and POST /v1/pair issues pairs"
             : "ACCEPTED as anything (no --token-key, no DROPSSH_RELAY_KEY). "
               "This is the historical behaviour; configure a key to enforce "
               "roles and to issue pairs.");
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
    /* ⛔ THE SOCKS LISTENER IS BOUND AND SERVED BY A THREAD OF ITS OWN, AND IT
     * IS OPTIONAL IN THE STRICTEST SENSE: a relay without --socks never binds
     * it, never reads a SOCKS byte, and has the same attack surface it had
     * before this existed.
     *
     * It is a separate listener rather than a path on the websocket listener
     * because the two protocols share nothing: a SOCKS greeting is three
     * bytes and an HTTP upgrade is a header block, and a parser that could
     * tell them apart by sniffing would be a parser with two grammars and one
     * set of bugs. */
    if (socks_listen_arg != NULL) {
        if (socks_node_arg == NULL || socks_dest_arg == NULL) {
            fprintf(stderr, "dropssh relay: --socks needs --socks-node (whose "
                    "node to reach through) and --socks-dest HOST:PORT (what "
                    "it is allowed to reach). Refusing to start a listener "
                    "with no policy, because a SOCKS5 proxy that dials what it "
                    "is asked to dial is an open proxy.\n");
            return 2;
        }
        snprintf(socks_node_name, sizeof socks_node_name, "%s", socks_node_arg);
        char dhost[256] = "";
        int dport = 0;
        struct in_addr dummy_addr;
        if (sscanf(socks_dest_arg, "%255[^:]:%d", dhost, &dport) != 2 ||
            dhost[0] == 0 || dport <= 0 || dport > 65535) {
            fprintf(stderr, "dropssh relay: --socks-dest wants HOST:PORT, and "
                    "'%s' is not one. The destination is NAMED rather than "
                    "taken from the request, so a client that asks for "
                    "anything else is refused.\n", socks_dest_arg);
            return 2;
        }
        snprintf(socks_host, sizeof socks_host, "%s", dhost);
        socks_port = dport;
        /* ⛔ A DESTINATION IS REFUSED IF IT CANNOT BE AN ADDRESS OR A NAME. The
         * check is here, before the listener is created, and that ordering is
         * the point: on a host that cannot bind INET -- which is every
         * reference cage, dropssh#6 measured 24/24 -- a bind failure comes
         * first and a policy that was never validated is never reported. So a
         * typo in `--socks-dest` has to be refused by this line, not by the
         * comparison three hundred lines later where it would look like a
         * client asking for the wrong thing. */
        if (inet_pton(AF_INET, dhost, &dummy_addr) != 1) {
            for (const char *c = dhost; *c; c++) {
                if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
                      (*c >= '0' && *c <= '9') || *c == '.' || *c == '-' ||
                      *c == '_')) {
                    fprintf(stderr, "dropssh relay: --socks-dest host '%s' "
                            "contains a character that is neither a dotted "
                            "quad nor a domain name.\n", dhost);
                    return 2;
                }
            }
        }

        char lhost[128] = "127.0.0.1";
        int lport = 1080;
        if (socks_listen_arg[0] != ':') {
            sscanf(socks_listen_arg, "%127[^:]:%d", lhost, &lport);
        } else {
            lport = atoi(socks_listen_arg + 1);
        }
        if (lport <= 0 || lport > 65535) {
            fprintf(stderr, "dropssh relay: --socks wants a port in "
                    "1..65535.\n");
            return 2;
        }
        socks_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socks_listen_fd < 0) {
            logf("socks socket: %s", strerror(errno));
            return 1;
        }
        int one = 1;
        setsockopt(socks_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in ssa;
        memset(&ssa, 0, sizeof ssa);
        ssa.sin_family = AF_INET;
        ssa.sin_port = htons((uint16_t)lport);
        ssa.sin_addr.s_addr = inet_addr(lhost[0] ? lhost : "127.0.0.1");
        if (bind(socks_listen_fd, (struct sockaddr *)&ssa, sizeof ssa) != 0) {
            logf("socks bind %s:%d: %s", lhost, lport, strerror(errno));
            return 1;
        }
        if (listen(socks_listen_fd, 16) != 0) {
            logf("socks listen: %s", strerror(errno));
            return 1;
        }
        logf("SOCKS5 on %s:%d, reaching %s:%d through node %s", lhost, lport,
             socks_host, socks_port, socks_node_name);
        logf("SOCKS5: a relay that restarts forgets its forwards, and a client "
             "asking for anything other than %s:%d is refused with SOCKS 0x02",
             socks_host, socks_port);
        {
            pthread_t sth;
            if (pthread_create(&sth, NULL, socks_accept_thread, NULL) != 0) {
                logf("socks: could not start the accept thread; the relay is "
                     "running without a SOCKS listener");
            } else {
                pthread_detach(sth);
            }
        }
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
