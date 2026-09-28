/* transport.c - TCP, an HTTP CONNECT proxy, and TLS over both.
 *
 * WHY THE PROXY PATH SENDS THE NAME UNRESOLVED. Measured 2026-09-27 in the
 * reference cage:
 *
 *   getaddrinfo("tcp.ssh.relay.ajam.dev")  -> Temporary failure
 *   getaddrinfo("tcp-1.ssh.relay.ajam.dev")-> Temporary failure
 *   CONNECT tcp.ssh.relay.ajam.dev:443     -> 200 Connection Established
 *   CONNECT tcp-1.ssh.relay.ajam.dev:443   -> 504 the name did not resolve
 *
 * The same proxy answers for one name and not the other, so the name is not
 * something the cage can settle and something to be handed over. A client
 * that resolves locally and then asks the proxy for a literal address would
 * work for the first name and fail for the second for a reason that looks
 * like the second relay being down.
 *
 * A literal address is still available, for the case where the cage does have
 * a resolver and the operator wants the proxy out of the path: pass
 * `ip_literal` and the name is not looked up anywhere.
 */
#include "transport.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>

/* -------------------------------------------------------------- socket I/O */
typedef struct {
    int fd;
} sockstate;

static int sock_read(Transport *t, void *buf, size_t len, size_t *out, int *eof) {
    sockstate *s = t->state;
    ssize_t n;
    *eof = 0;
    *out = 0;
    do {
        n = read(s->fd, buf, len);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;         /* nothing yet, and that is not an error */
        }
        return -1;
    }
    if (n == 0) {
        *eof = 1;
        return 0;
    }
    *out = (size_t)n;
    return 0;
}

static int sock_write(Transport *t, const void *buf, size_t len) {
    sockstate *s = t->state;
    const unsigned char *p = buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n;
        do {
            n = write(s->fd, p + done, len - done);
        } while (n < 0 && errno == EINTR);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pf = { .fd = s->fd, .events = POLLOUT };
                if (poll(&pf, 1, 30000) <= 0) {
                    return -1;
                }
                continue;
            }
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

static void sock_close(Transport *t) {
    sockstate *s = t->state;
    if (s) {
        if (s->fd >= 0) {
            close(s->fd);
        }
        free(s);
    }
    free(t);
}

static void sock_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) {
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
}

/* Wait for a socket to become writable, bounded. Connect itself is bounded by
 * a non-blocking connect plus this poll, because a blocking connect to a
 * filtered route can sit for the kernel's own two minutes. */
static int wait_writable(int fd, int ms) {
    struct pollfd pf = { .fd = fd, .events = POLLOUT };
    int r;
    do {
        r = poll(&pf, 1, ms);
    } while (r < 0 && errno == EINTR);
    if (r <= 0) {
        return -1;
    }
    int err = 0;
    socklen_t elen = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0) {
        return -1;
    }
    if (err != 0) {
        errno = err;
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------- dialing */
static int dial_one(const char *host, int port, int family,
                    int connect_ms, char *err, size_t errlen) {
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);

    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0 || res == NULL) {
        /* ⛔ THIS IS WHERE A CAGE WITH NO RESOLVER LANDS, AND THE MESSAGE
         * SAYS SO RATHER THAN SAYING "CONNECTION REFUSED". The two need
         * different things from the operator: one means the cage cannot
         * resolve and the proxy is the way out, the other means the target
         * said no. */
        snprintf(err, errlen, "cannot resolve %s: %s", host,
                 gai_strerror(gai));
        return -1;
    }
    int last = EHOSTUNREACH;
    for (ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last = errno;
            continue;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        sock_nonblock(fd);
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r != 0 && errno == EINPROGRESS) {
            if (wait_writable(fd, connect_ms) != 0) {
                last = errno ? errno : ETIMEDOUT;
                close(fd);
                continue;
            }
            r = 0;
        }
        if (r != 0) {
            last = errno;
            close(fd);
            continue;
        }
        freeaddrinfo(res);
        return fd;
    }
    freeaddrinfo(res);
    snprintf(err, errlen, "cannot connect to %s:%d: %s", host, port,
             strerror(last));
    return -1;
}

static Transport *wrap_fd(int fd, const char *name, int family) {
    Transport *t = calloc(1, sizeof *t);
    sockstate *s = calloc(1, sizeof *s);
    if (t == NULL || s == NULL) {
        free(t);
        free(s);
        close(fd);
        return NULL;
    }
    /* ⛔ EVERY SOCKET IS NON-BLOCKING, AND IT IS DONE HERE, ONCE, IN THE ONE
     * PLACE A TRANSPORT IS BUILT. Three of the four constructors bypassed it:
     * transport_tcp_unix and transport_from_fd called wrap_fd directly, and
     * only dial_one set the flag. So a unix-socket relay and every socket the
     * relay accepted were BLOCKING, and sock_read's contract ("return 0 bytes
     * and eof=0 rather than waiting") was a lie for them: read() simply sat
     * there.
     *
     * The blocking `ws_read` hid this, because it was written to wait. The
     * multiplexed operator cannot wait: it has to service stdin while waiting
     * for the node's reply, and a socket that blocks in read() starves stdin
     * for as long as the peer is quiet. Measured: the operator read 1000 bytes
     * of a 3658-byte stream and then stopped, with every log line correct.
     *
     * So the property is established where the object is created rather than
     * at each call site, because a call site that forgets it is invisible. */
    sock_nonblock(fd);
    s->fd = fd;
    t->name = name;
    t->state = s;
    t->read = sock_read;
    t->write = sock_write;
    t->close = sock_close;
    t->is_tls = 0;
    t->family = family;
    t->read_can_block = 0;
    return t;
}

Transport *transport_from_fd(int fd, const char *name) {
    sock_nonblock(fd);
    return wrap_fd(fd, name ? name : "fd", 0);
}

Transport *transport_tcp_unix(const char *path, char *err, size_t errlen) {
    /* A local relay is a unix socket, not a network peer, so it skips the
     * proxy AND the TLS. Sending a loopback websocket through an egress
     * proxy and a certificate handshake would make the local path depend on
     * the very things the local path exists to avoid, and would fail in a cage
     * that has neither. */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(err, errlen, "socket(AF_UNIX): %s", strerror(errno));
        return NULL;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        snprintf(err, errlen, "cannot reach the relay at %s: %s", path,
                 strerror(errno));
        close(fd);
        return NULL;
    }
    return wrap_fd(fd, "relay", 0);
}

Transport *transport_tcp(const char *host, int port,
                         const char *proxy_host, int proxy_port,
                         int connect_ms, char *err, size_t errlen) {
    if (proxy_host == NULL || proxy_host[0] == 0) {
        int fd = dial_one(host, port, AF_UNSPEC, connect_ms, err, errlen);
        if (fd < 0) {
            return NULL;
        }
        return wrap_fd(fd, "tcp", 0);
    }

    int pfd = dial_one(proxy_host, proxy_port, AF_UNSPEC, connect_ms, err, errlen);
    if (pfd < 0) {
        snprintf(err, errlen, "cannot reach proxy %s:%d: %s",
                 proxy_host, proxy_port, err);
        return NULL;
    }
    /* ⛔ THE REQUEST LINE CARRIES THE NAME, NOT AN ADDRESS, ON PURPOSE. See
     * the header: a cage with no resolver can only work if the peer resolves,
     * and asking the peer for a literal address is what produced the
     * 200-here/504-there behaviour that reads like a dead relay. */
    char req[1024];
    int n = snprintf(req, sizeof req,
                     "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
                     "Proxy-Connection: keep-alive\r\n\r\n",
                     host, port, host, port);
    if (n < 0 || (size_t)n >= sizeof req) {
        snprintf(err, errlen, "proxy request for %s:%d is too long to build", host, port);
        close(pfd);
        return NULL;
    }
    /* The socket is non-blocking, so the request goes out in pieces and the
     * response is read a line at a time with a bounded wait. */
    size_t sent = 0;
    while (sent < (size_t)n) {
        ssize_t w = write(pfd, req + sent, (size_t)n - sent);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_writable(pfd, connect_ms) != 0) {
                    snprintf(err, errlen, "proxy write timed out");
                    close(pfd);
                    return NULL;
                }
                continue;
            }
            snprintf(err, errlen, "proxy write failed: %s", strerror(errno));
            close(pfd);
            return NULL;
        }
        sent += (size_t)w;
    }

    char head[4096];
    size_t got = 0;
    unsigned long waited = 0;
    while (got + 1 < sizeof head) {
        if (waited > (unsigned long)connect_ms) {
            snprintf(err, errlen, "proxy did not answer CONNECT within %dms", connect_ms);
            close(pfd);
            return NULL;
        }
        ssize_t r = read(pfd, head + got, sizeof head - 1 - got);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                waited += 50;
                struct pollfd pf = { .fd = pfd, .events = POLLIN };
                poll(&pf, 1, 50);
                continue;
            }
            snprintf(err, errlen, "proxy read failed: %s", strerror(errno));
            close(pfd);
            return NULL;
        }
        if (r == 0) {
            snprintf(err, errlen, "proxy closed during CONNECT");
            close(pfd);
            return NULL;
        }
        got += (size_t)r;
        head[got] = 0;
        if (strstr(head, "\r\n\r\n")) {
            break;
        }
    }
    head[got] = 0;
    if (strncmp(head, "HTTP/1.", 7) != 0 || strstr(head, " 200") == NULL) {
        /* ⛔ THE PROXY'S OWN LINE IS QUOTED, TRUNCATED TO ONE LINE. "503" and
         * "407" and "504" each mean something specific, and a message that
         * collapses them into "proxy refused" costs the operator the one
         * fact that would have told them what to do. */
        char line[200];
        size_t i = 0;
        while (i + 1 < sizeof line && head[i] && head[i] != '\r' && head[i] != '\n') {
            line[i] = head[i];
            i++;
        }
        line[i] = 0;
        snprintf(err, errlen, "proxy refused CONNECT to %s:%d: %s", host, port, line);
        close(pfd);
        return NULL;
    }
    return wrap_fd(pfd, "proxy", 0);
}
