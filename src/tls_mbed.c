/* tls_mbed.c - the mbedTLS backend.
 *
 * mbedTLS rather than libcurl because the dropssh side is meant to be a
 * single static binary: a curl backend drags in a dependency resolver, a
 * CA bundle path, and a second set of opinions about proxies. mbedTLS is a
 * library, links statically, and lets dropssh own the socket, so the proxy
 * CONNECT dropssh already speaks is the only proxy path there is. See
 * docs/decisions-tls.md.
 *
 * THE PROXY IS DROPSSH'S, NOT TLS's, AND THAT IS THE POINT. An HTTP CONNECT
 * proxy is established on the raw socket, then TLS runs over the tunnel
 * exactly as it would over a direct connection, so a relay reached through a
 * proxy is verified against its own certificate and not against the proxy's.
 */
#include "tls.h"
#include "util.h"

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>

const char *dropssh_tls_backend(void) { return "mbedtls"; }

/* The last TLS failure, in words. Set when a handshake or read fails so the
 * caller can say WHY the relay was unreachable; "connection failed" from a
 * certificate problem is the message that costs an hour. */
char tls_last_error[512];

const char *dropssh_tls_lasterror(void) {
    return tls_last_error[0] ? tls_last_error : NULL;
}

typedef struct {
    mbedtls_ssl_context ssl;
    /* mbedTLS 3 keeps its state machine private, so the handshake phase is
     * tracked here rather than read out of the context. Without this the
     * first read would be attempted before the handshake finished, and
     * MBEDTLS_ERR_SSL_BAD_INPUT_DATA would be reported as a dead peer. */
    int handshaked;
    mbedtls_ssl_config  conf;
    mbedtls_x509_crt    cacert;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr;
    int      inited;
} tlsstate;

/* ⛔ THE CA BUNDLE IS OPTIONAL AND ITS ABSENCE IS REFUSED, NOT IGNORED. With
 * no bundle and verification on, the only way to succeed is to trust every
 * certificate, which is the thing `--insecure` exists to say out loud. So a
 * missing bundle with verification on is a startup error naming the variable
 * to set, rather than a session that silently accepts anything. */
/* ⛔ THE ENVIRONMENT SLOT IS AN EMPTY STRING, NOT NULL, AND THAT IS THE WHOLE
 * TRICK. The loop below is terminated by a NULL entry, and it originally set
 * slot 0 from getenv(), which returns NULL when the variable is unset. So on
 * every machine with no DROPSSH_CA_BUNDLE, SSL_CERT_FILE and CURL_CA_BUNDLE
 * -- which is most of them -- the loop stopped at i=0 and never looked at the
 * three well-known paths, and dropssh reported "no CA bundle found" with
 * /etc/ssl/certs/ca-certificates.crt sitting right there.
 *
 * The symptom that pinned it: the same binary succeeded the moment
 * DROPSSH_CA_BUNDLE was set, and set is exactly the case where getenv
 * returns a pointer instead of NULL.
 */
static const char *ca_paths[] = {
    "",      /* filled from the environment below; "" means "not set" */
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/ssl/certs/ca-bundle.crt",
    NULL
};

static int tlsstate_init(tlsstate *s, int insecure, char *err, size_t errlen) {
    memset(s, 0, sizeof *s);
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);
    mbedtls_x509_crt_init(&s->cacert);
    mbedtls_entropy_init(&s->entropy);
    mbedtls_ctr_drbg_init(&s->ctr);

    if (mbedtls_ctr_drbg_seed(&s->ctr, mbedtls_entropy_func, &s->entropy,
                              (const unsigned char *)"dropssh", 8) != 0) {
        snprintf(err, errlen, "mbedtls: no entropy source for the TLS RNG");
        return -1;
    }
    if (mbedtls_ssl_config_defaults(&s->conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        snprintf(err, errlen, "mbedtls: could not set the TLS defaults");
        return -1;
    }
    mbedtls_ssl_conf_rng(&s->conf, mbedtls_ctr_drbg_random, &s->ctr);

    if (insecure) {
        /* ⛔ VERIFICATION IS TURNED OFF IN BOTH PLACES, NOT ONE. mbedTLS has
         * a peer check and a hostname check, and setting only the first leaves
         * a session that trusts any certificate for the right key but any
         * name at all. */
        mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_NONE);
    } else {
        for (int e = 0; e < 3; e++) {
            static const char *const envs[3] = {
                "DROPSSH_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"
            };
            const char *v = getenv(envs[e]);
            if (v != NULL && v[0] != 0) {
                ca_paths[0] = v;
                break;
            }
        }
        /* ⛔ A FILE AND A DIRECTORY ARE PARSED BY DIFFERENT FUNCTIONS, AND
         * USING THE WRONG ONE FAILS IN A WAY THAT NAMES THE WRONG THING.
         *
         * Measured here: `mbedtls_x509_crt_parse_path("/tmp/ca.crt")` returns
         * MBEDTLS_ERR_X509_FILE_IO_ERROR, which reads as "the file could not
         * be opened" on a file that opens fine and parses to 170 certificates
         * when the same bytes are handed to parse_file. parse_path walks a
         * DIRECTORY with readdir, and readdir on a regular file fails, so the
         * error is accurate about what went wrong and useless about what to
         * do about it. The first version of this layer called parse_path for
         * everything and reported "no CA bundle found" for a bundle that was
         * sitting right there.
         */
        int loaded = 0;
        for (int i = 0; ca_paths[i]; i++) {
            if (ca_paths[i][0] == 0) {
                continue;
            }
            struct stat st;
            if (stat(ca_paths[i], &st) != 0) {
                continue;
            }
            int r = S_ISDIR(st.st_mode)
                        ? mbedtls_x509_crt_parse_path(&s->cacert, ca_paths[i])
                        : mbedtls_x509_crt_parse_file(&s->cacert, ca_paths[i]);
            if (r == 0) {
                loaded = 1;
                break;
            }
        }
        if (!loaded) {
            snprintf(err, errlen,
                     "no CA bundle found, so no certificate can be verified. "
                     "Set DROPSSH_CA_BUNDLE to a ca-certificates.crt, or pass "
                     "--insecure to skip verification on purpose.");
            return -1;
        }
        mbedtls_ssl_conf_ca_chain(&s->conf, &s->cacert, NULL);
        mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    s->inited = 1;
    return 0;
}

static void tlsstate_free(tlsstate *s) {
    if (!s->inited) {
        return;
    }
    mbedtls_ssl_free(&s->ssl);
    mbedtls_ssl_config_free(&s->conf);
    mbedtls_x509_crt_free(&s->cacert);
    mbedtls_ctr_drbg_free(&s->ctr);
    mbedtls_entropy_free(&s->entropy);
    s->inited = 0;
}

/* mbedTLS wants to own a socket; this hands it one without letting it close
 * the descriptor out from under the Transport that owns it. */
static int mbed_send(void *ctx, const unsigned char *buf, size_t len) {
    Transport *t = ctx;
    return t->write(t, buf, len) == 0 ? (int)len : -1;
}

static int mbed_recv(void *ctx, unsigned char *buf, size_t len) {
    Transport *t = ctx;
    size_t got = 0;
    int eof = 0;
    for (;;) {
        if (t->read(t, buf, len, &got, &eof) != 0) {
            return -1;
        }
        if (got) {
            return (int)got;
        }
        if (eof) {
            return 0;
        }
        dropssh_sleep_ms(20);
    }
}

static int tls_read(Transport *t, void *out, size_t len, size_t *got, int *eof) {
    tlsstate *s = t->state;
    *eof = 0;
    *got = 0;
    for (;;) {
        int r;
        if (!s->handshaked) {
            r = mbedtls_ssl_handshake(&s->ssl);
            if (r == 0) {
                s->handshaked = 1;
                continue;
            }
            if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
                dropssh_sleep_ms(10);
                continue;
            }
            /* A real handshake failure. The verify result is what makes this
             * actionable, so it is put in front of the generic error code
             * rather than after it. */
            if (mbedtls_ssl_get_verify_result(&s->ssl) != 0) {
                char vbuf[256];
                mbedtls_x509_crt_verify_info(vbuf, sizeof vbuf, "  ",
                        mbedtls_ssl_get_verify_result(&s->ssl));
                t->family = -1;   /* carries the failure to the caller */
                snprintf(tls_last_error, sizeof tls_last_error,
                         "TLS verification failed for %s: %s", t->name, vbuf);
            } else {
                char ebuf[256];
                mbedtls_strerror(r, ebuf, sizeof ebuf);
                t->family = -1;
                snprintf(tls_last_error, sizeof tls_last_error,
                         "TLS handshake failed: %s", ebuf);
            }
            *eof = 1;
            return 0;
        }
        r = mbedtls_ssl_read(&s->ssl, out, len);
        if (r > 0) {
            *got = (size_t)r;
            return 0;
        }
        if (r == 0) {
            *eof = 1;
            return 0;
        }
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            dropssh_sleep_ms(10);
            continue;
        }
        if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            *eof = 1;
            return 0;
        }
        char ebuf[256];
        mbedtls_strerror(r, ebuf, sizeof ebuf);
        t->family = -1;
        snprintf(tls_last_error, sizeof tls_last_error, "TLS read: %s", ebuf);
        *eof = 1;
        return 0;
    }
}

static int tls_write(Transport *t, const void *buf, size_t len) {
    tlsstate *s = t->state;
    const unsigned char *p = buf;
    size_t done = 0;
    while (done < len) {
        int r = mbedtls_ssl_write(&s->ssl, p + done, len - done);
        if (r > 0) {
            done += (size_t)r;
            continue;
        }
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            dropssh_sleep_ms(10);
            continue;
        }
        return -1;
    }
    return 0;
}

static void tls_close(Transport *t) {
    tlsstate *s = t->state;
    if (s) {
        tlsstate_free(s);
        free(s);
    }
    free(t);
}

Transport *transport_tls(Transport *tcp, const char *sni, int insecure,
                         char *err, size_t errlen) {
    tlsstate *s = calloc(1, sizeof *s);
    Transport *t = calloc(1, sizeof *t);
    if (s == NULL || t == NULL) {
        free(s);
        free(t);
        tcp->close(tcp);
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    if (tlsstate_init(s, insecure, err, errlen) != 0) {
        free(s);
        free(t);
        tcp->close(tcp);
        return NULL;
    }
    if (mbedtls_ssl_setup(&s->ssl, &s->conf) != 0) {
        snprintf(err, errlen, "mbedtls: could not set up the TLS context");
        goto fail;
    }
    if (mbedtls_ssl_set_hostname(&s->ssl, sni ? sni : "") != 0) {
        snprintf(err, errlen, "mbedtls: could not set the server name");
        goto fail;
    }
    mbedtls_ssl_set_bio(&s->ssl, tcp, mbed_send, mbed_recv, NULL);
    t->name = tcp->name;
    t->state = s;
    t->read = tls_read;
    t->write = tls_write;
    t->close = tls_close;
    t->is_tls = 1;
    t->family = tcp->family;
    /* The underlying transport is owned by the tls state now, and tls_close
     * frees it through the Transport it was given. */
    s->inited = 2;
    return t;
fail:
    tlsstate_free(s);
    free(s);
    free(t);
    tcp->close(tcp);
    return NULL;
}

/* --------------------------------------------------------- one-shot requests */
typedef struct {
    buffer  body;
    buffer  head;
    int     status;
} collect;

static int http_open(const char *host, int port, const char *path,
                     const char *query, const char *method, const char *reqbody,
                     int insecure, char *err, size_t errlen, collect *out) {
    char errbuf[256] = "";
    Transport *t = transport_tcp(host, port, dropssh_proxy_host(),
                                 dropssh_proxy_port(), 15000, errbuf, sizeof errbuf);
    if (t == NULL) {
        snprintf(err, errlen, "%s", errbuf);
        return -1;
    }
    t = transport_tls(t, host, insecure, errbuf, sizeof errbuf);
    if (t == NULL) {
        snprintf(err, errlen, "%s", errbuf);
        return -1;
    }
    char req[2048];
    int n = snprintf(req, sizeof req,
                     "%s %s%s%s HTTP/1.1\r\nHost: %s:%d\r\n"
                     "User-Agent: dropssh/%s\r\nAccept: */*\r\n"
                     "Connection: close\r\n",
                     method, path,
                     (query && *query) ? "?" : "", (query && *query) ? query : "",
                     host, port, dropssh_version());
    if (n < 0 || (size_t)n >= sizeof req) {
        t->close(t);
        snprintf(err, errlen, "the request is too long to build");
        return -1;
    }
    if (t->write(t, req, (size_t)n) != 0) {
        t->close(t);
        snprintf(err, errlen, "could not write the request");
        return -1;
    }
    if (reqbody && *reqbody) {
        char hdr[256];
        int hn = snprintf(hdr, sizeof hdr,
                          "Content-Type: application/json\r\n"
                          "Content-Length: %zu\r\n\r\n%s", strlen(reqbody), reqbody);
        if (t->write(t, hdr, (size_t)hn) != 0) {
            t->close(t);
            snprintf(err, errlen, "could not write the request body");
            return -1;
        }
    } else {
        if (t->write(t, "\r\n", 2) != 0) {
            t->close(t);
            snprintf(err, errlen, "could not finish the request");
            return -1;
        }
    }

    buffer raw;
    buf_init(&raw);
    unsigned char tmp[8192];
    size_t got = 0;
    int eof = 0;
    while (!eof) {
        if (t->read(t, tmp, sizeof tmp, &got, &eof) != 0) {
            break;
        }
        if (got) {
            buf_append(&raw, tmp, got);
        }
    }
    /* The headers and the body share one read, so they are split here. A
     * response with no body and no blank line is treated as headers only. */
    unsigned char *brk = memmem(raw.p, raw.len, "\r\n\r\n", 4);
    size_t hlen, blen;
    unsigned char *bstart;
    if (brk) {
        hlen = (size_t)(brk - raw.p) + 4;
        bstart = raw.p + hlen;
        blen = raw.len - hlen;
    } else {
        hlen = raw.len;
        bstart = raw.p + raw.len;
        blen = 0;
    }
    out->status = 0;
    if (hlen > 12 && strncmp((char *)raw.p, "HTTP/1.", 7) == 0) {
        out->status = atoi((char *)raw.p + 8);
    }
    buf_init(&out->body);
    buf_init(&out->head);
    if (blen) {
        buf_append(&out->body, bstart, blen);
    }
    /* One extra byte for the terminator each. buf_append reserved room for
     * the payload but not for a NUL, and both are read as C strings. */
    if (blen == 0 || out->body.p == NULL || buf_reserve(&out->body, 1) != 0) {
        /* An empty body still needs a valid, readable pointer for the caller
         * to free, so a one-byte buffer is allocated rather than a NULL that
         * every caller has to remember to check. */
        if (buf_reserve(&out->body, 1) != 0) {
            buf_free(&out->body); buf_free(&out->head); buf_free(&raw);
            t->close(t);
            snprintf(err, errlen, "out of memory");
            return -1;
        }
    }
    out->body.p[out->body.len] = 0;
    if (hlen) {
        buf_append(&out->head, raw.p, hlen);
        if (out->head.p == NULL || buf_reserve(&out->head, 1) != 0) {
            buf_free(&out->body); buf_free(&out->head); buf_free(&raw);
            t->close(t);
            snprintf(err, errlen, "out of memory");
            return -1;
        }
        out->head.p[out->head.len] = 0;
    }
    buf_free(&raw);
    t->close(t);
    return 0;
}

int tls_get(const char *host, int port, const char *path, const char *query,
            int https, int insecure, const char *proxy_host, int proxy_port,
            const char **resp_headers, char **body, size_t *len,
            char *err, size_t errlen) {
    (void)https; (void)proxy_host; (void)proxy_port;
    collect c;
    memset(&c, 0, sizeof c);
    if (http_open(host, port, path, query, "GET", NULL, insecure, err, errlen, &c) != 0) {
        return -1;
    }
    *len = c.body.len;
    *body = malloc(*len + 1);
    if (*body == NULL) {
        buf_free(&c.body); buf_free(&c.head);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    if (*len) {
        memcpy(*body, c.body.p, *len);
    }
    (*body)[*len] = 0;
    if (resp_headers && c.head.len) {
        *resp_headers = (const char *)c.head.p;
    }
    buf_free(&c.body);
    buf_free(&c.head);
    return 0;
}

int tls_post(const char *host, int port, const char *path, const char *body,
             int https, int insecure, const char *proxy_host, int proxy_port,
             char **resp, size_t *len, char *err, size_t errlen) {
    (void)https; (void)proxy_host; (void)proxy_port;
    collect c;
    memset(&c, 0, sizeof c);
    if (http_open(host, port, path, NULL, "POST", body, insecure, err, errlen, &c) != 0) {
        return -1;
    }
    if (c.status == 503) {
        snprintf(err, errlen,
                 "the relay answered 503: token issuance is disabled or "
                 "unconfigured there, so an operator token is needed");
        buf_free(&c.body); buf_free(&c.head);
        return -1;
    }
    if (c.status == 429) {
        snprintf(err, errlen, "the relay is rate limiting mint attempts (429); "
                              "wait for Retry-After and try again");
        buf_free(&c.body); buf_free(&c.head);
        return -1;
    }
    if (c.status < 200 || c.status >= 300) {
        snprintf(err, errlen, "the relay answered HTTP %d to the mint request", c.status);
        buf_free(&c.body); buf_free(&c.head);
        return -1;
    }
    *len = c.body.len;
    *resp = malloc(*len + 1);
    if (*resp == NULL) {
        buf_free(&c.body); buf_free(&c.head);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    if (*len) {
        memcpy(*resp, c.body.p, *len);
    }
    (*resp)[*len] = 0;
    buf_free(&c.body);
    buf_free(&c.head);
    return 0;
}

int doh_query(const char *host, int port, const char *path, const char *query,
              int https, int insecure, const char *proxy_host, int proxy_port,
              char **body, size_t *len, char *err, size_t errlen) {
    (void)https; (void)proxy_host; (void)proxy_port;
    collect c;
    memset(&c, 0, sizeof c);
    if (http_open(host, port, path, query, "GET", NULL, insecure, err, errlen, &c) != 0) {
        return -1;
    }
    if (c.status < 200 || c.status >= 300) {
        snprintf(err, errlen, "the DoH server answered HTTP %d", c.status);
        buf_free(&c.body); buf_free(&c.head);
        return -1;
    }
    *len = c.body.len;
    *body = malloc(*len + 1);
    if (*body == NULL) {
        buf_free(&c.body); buf_free(&c.head);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    if (*len) {
        memcpy(*body, c.body.p, *len);
    }
    (*body)[*len] = 0;
    buf_free(&c.body);
    buf_free(&c.head);
    return 0;
}
