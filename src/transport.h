/* transport.h - one byte pipe, four ways, and the resolver that feeds them.
 *
 * A cage's egress is not uniform. It may allow TCP straight out, or only
 * through an HTTP proxy, or only through a proxy that resolves names ITSELF
 * because the cage has no resolver at all. Measured in the reference cage
 * 2026-09-27, which is the third case:
 *
 *   getaddrinfo("tcp.ssh.relay.ajam.dev") -> Temporary failure in name
 *                                           resolution
 *   CONNECT tcp.ssh.relay.ajam.dev:443 via the host proxy -> 200
 *   CONNECT tcp-1.ssh.relay.ajam.dev:443 via the same proxy
 *                                     -> 504 the name did not resolve in time
 *
 * So "use a proxy" is not enough. The proxy resolves, and whether it answers
 * for a name is a property of the path, not of the name. Hence the four
 * routes below and the fallback order that tries them.
 */
#ifndef DROPSSH_TRANSPORT_H
#define DROPSSH_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

/* A growable byte buffer. Every layer here moves unknown-length bytes between
 * a socket and a frame decoder, so the buffer is the interface, not a
 * convenience. */
typedef struct {
    unsigned char *p;
    size_t len;
    size_t cap;
    size_t at;     /* read cursor; the buffer compacts itself when at > 4096 */
} buffer;

void  buf_init(buffer *b);
void  buf_free(buffer *b);
int   buf_reserve(buffer *b, size_t extra);
int   buf_append(buffer *b, const void *data, size_t len);
void  buf_consume(buffer *b, size_t n);
void  buf_reset(buffer *b);

typedef struct Transport Transport;

/* ⛔ HAND THE RAW DESCRIPTOR TO THE CALLER AND GIVE UP OWNERSHIP OF IT. Used
 * where a session pumps a socket itself rather than through the Transport:
 * dropbear's socketpair, and a SOCKS forward's dialed connection. Returns -1
 * for a TLS transport, whose "descriptor" is an mbedTLS session and handing
 * the pointer over would hand the caller ciphertext. */
int transport_detach_fd(Transport *t);

/* ⛔ READ AND WRITE NEVER REPORT "TIMED OUT" AS AN ERROR. A websocket frame
 * header can arrive seconds after the last byte, and a relay that answered in
 * 350 ms can then go quiet for a minute. The transport returns 0 bytes and the
 * caller decides what silence means, because a timeout that is reported as a
 * failure is a session that dies while the operator is reading. */
struct Transport {
    const char *name;          /* for error text: "tcp", "proxy", "relay" */
    void *state;               /* transport-private */
    int (*read)(Transport *t, void *buf, size_t len, size_t *out, int *eof);
    int (*write)(Transport *t, const void *buf, size_t len);
    void (*close)(Transport *t);
    int  is_tls;
    int  family;               /* 4, 6, or 0 for "not a socket" */
    /* ⛔ WHETHER read() MAY BLOCK, DECLARED BY THE TRANSPORT AND NOT ASSUMED.
     * A plain socket read returns immediately with 0 bytes when nothing has
     * arrived, because the descriptor is non-blocking. A TLS read CANNOT: it
     * calls into the library, which asks the socket for more, is told to wait,
     * and the first version answered that by sleeping 10 ms and asking again,
     * for ever. So a caller that must not block cannot tell from the return
     * value whether "nothing yet" is instant or is a wait.
     *
     * That is not a theoretical difference. The multiplexed operator has to
     * service stdin while waiting for the node, and against the ajam relay --
     * which is TLS -- the operator received the node's banner, released its
     * ready gate, and then stopped: the third ws_poll_frame call never
     * returned, so the operator's ssh banner and KEXINIT were never sent and
     * the session hung with every log line correct. Against a local unix relay
     * the same code worked perfectly, which is why the whole multiplexer was
     * proven locally and then failed live.
     *
     * So the property is a field the transport sets, and a caller that must
     * not block checks it. */
    int  read_can_block;
};

typedef enum {
    ROUTE_DIRECT = 0,   /* straight TCP to the target */
    ROUTE_PROXY,        /* HTTP CONNECT to a proxy, name or literal address */
    ROUTE_RELAY,        /* websocket to the ajam relay, which dials the target */
    ROUTE_LAST
} route_kind;

typedef struct {
    route_kind kind;
    const char *host;        /* target host, or the relay host for ROUTE_RELAY */
    int         port;
    const char *path;        /* relay request target, e.g. "/connect/railway" */
    const char *token;       /* X-Relay-Token, or NULL */
    const char *proxy_host;  /* for ROUTE_PROXY */
    int         proxy_port;
    const char *family;      /* "4", "6", or NULL for auto */
    int         insecure;    /* skip certificate verification */
    int         connect_ms;
    const char *sni;         /* override the TLS server name */
} Route;

/* Open a TCP socket, honouring an HTTP proxy when one is configured.
 *
 * ⛔ WHEN A PROXY IS USED THE NAME IS SENT TO THE PROXY UNRESOLVED AND THE
 * PROXY IS ASKED TO RESOLVE IT. That is not a shortcut, it is the only thing
 * that works where the cage has no resolver, and it is also why a proxy
 * answers 504 for one name and 200 for another. `host` is therefore passed
 * through verbatim and the literal-address path is chosen explicitly with
 * `ip_literal`.
 */
Transport *transport_tcp(const char *host, int port,
                         const char *proxy_host, int proxy_port,
                         int connect_ms, char *err, size_t errlen);

/* A relay that is a unix socket on this machine. No proxy, no TLS: see
 * transport_tcp_unix. */
Transport *transport_tcp_unix(const char *path, char *err, size_t errlen);

Transport *transport_tls(Transport *tcp, const char *sni, int insecure,
                         char *err, size_t errlen);

/* Adopt a socket this process already accepted, rather than dialled. The relay
 * needs this: it accepts connections rather than making them, and wrapping the
 * accepted descriptor in the same Transport is what lets the relay and the
 * node share one websocket implementation instead of two. */
Transport *transport_from_fd(int fd, const char *name);

/* Open a route end to end, including TLS for ROUTE_RELAY, and say in `used`
 * which kind actually worked. */
Transport *transport_open(const Route *r, route_kind *used,
                          char *err, size_t errlen);

/* ------------------------------------------------------------------ resolve
 * A cage may have no resolver at all, and a proxy may or may not resolve for
 * it. This layer asks, in order, and reports which one answered:
 *
 *   1. getaddrinfo, when a resolver exists
 *   2. /etc/hosts, because a cage that has one has usually curated it
 *   3. DoH over the same proxy the transport uses, HTTPS only
 *
 * The DoH answers are cached, because a session that re-resolves on every
 * reconnect is a session that pays the round trip every time, and the answer
 * for a relay's own name changes on the order of hours. */
typedef struct {
    int      family;          /* 4 or 6 */
    unsigned char addr[16];   /* IPv4 in the first 4 bytes, as in struct sockaddr */
} HostAddr;

/* Returns 0 on success, writing up to `max` addresses. `how` names the
 * source: "getaddrinfo", "hosts", "doh" or "proxy", and a caller that logs it
 * learns why a name resolved rather than assuming it did. */
int dropssh_resolve(const char *host, HostAddr *out, int max,
                    const char *doh_url, const char *proxy_host, int proxy_port,
                    const char **how, char *err, size_t errlen);

void dropssh_forget_dns(void);

#endif /* DROPSSH_TRANSPORT_H */
