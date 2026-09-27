/* util.c - see util.h. */
#define _GNU_SOURCE
#include "util.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef DROPSSH_VERSION
#define DROPSSH_VERSION "0.1.0"
#endif
#ifndef DROPSSH_GITDESCRIBE
#define DROPSSH_GITDESCRIBE "unknown"
#endif

const char *dropssh_version(void) { return DROPSSH_VERSION; }
const char *dropssh_gitdescribe(void) { return DROPSSH_GITDESCRIBE; }

static const char b64tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void dropssh_b64_encode(const unsigned char *in, size_t len, char *out,
                        size_t outlen) {
    size_t o = 0;
    size_t i = 0;
    while (i + 2 < len && o + 4 < outlen) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = b64tab[(v >> 18) & 63];
        out[o++] = b64tab[(v >> 12) & 63];
        out[o++] = b64tab[(v >> 6) & 63];
        out[o++] = b64tab[v & 63];
        i += 3;
    }
    if (i < len && o + 4 < outlen) {
        uint32_t v = (uint32_t)in[i] << 16;
        int have2 = (i + 1 < len);
        if (have2) {
            v |= (uint32_t)in[i + 1] << 8;
        }
        out[o++] = b64tab[(v >> 18) & 63];
        out[o++] = b64tab[(v >> 12) & 63];
        out[o++] = have2 ? b64tab[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    if (o < outlen) {
        out[o] = 0;
    } else if (outlen) {
        out[outlen - 1] = 0;
    }
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int dropssh_b64_decode(const char *in, unsigned char *out, size_t outlen,
                       size_t *outlen_out) {
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (const char *p = in; *p; p++) {
        if (*p == '=' || *p == '\n' || *p == '\r') {
            continue;
        }
        int v = b64val(*p);
        if (v < 0) {
            return -1;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outlen) {
                return -1;
            }
            out[o++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    if (outlen_out) {
        *outlen_out = o;
    }
    return 0;
}

void dropssh_random(void *out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;
    if (fd >= 0) {
        while (got < len) {
            ssize_t n = read(fd, (unsigned char *)out + got, len - got);
            if (n <= 0) {
                break;
            }
            got += (size_t)n;
        }
        close(fd);
    }
    if (got < len) {
        /* ⛔ THE FALLBACK IS /dev/urandom THROUGH A SECOND PATH, THEN ABORTS.
         * It is not seeded from the clock: a nonce an attacker can narrow to a
         * second is a nonce an attacker can predict, and the one place this
         * matters is the Sec-WebSocket-Key, which is what proves the peer
         * understood the handshake. Better to fail than to send a guessable
         * key. */
        static const char *alts[] = { "/dev/random", NULL };
        for (int i = 0; alts[i] && got < len; i++) {
            int f2 = open(alts[i], O_RDONLY);
            if (f2 < 0) {
                continue;
            }
            while (got < len) {
                ssize_t n = read(f2, (unsigned char *)out + got, len - got);
                if (n <= 0) {
                    break;
                }
                got += (size_t)n;
            }
            close(f2);
        }
        if (got < len) {
            fprintf(stderr, "dropssh: no source of randomness; refusing to "
                            "start rather than send a predictable key\n");
            exit(70);
        }
    }
}

void dropssh_random_b64(char *out, size_t outlen, size_t nbytes) {
    unsigned char buf[64];
    if (nbytes > sizeof buf) {
        nbytes = sizeof buf;
    }
    dropssh_random(buf, nbytes);
    dropssh_b64_encode(buf, nbytes, out, outlen);
}

/* --- SHA-1, for Sec-WebSocket-Accept only. See the note in util.h. --- */
typedef struct {
    uint32_t h[5];
    uint64_t len;
    unsigned char blk[64];
    size_t blen;
} sha1_ctx;

static uint32_t rol(uint32_t v, int b) {
    return (v << b) | (v >> (32 - b));
}

static void sha1_block(sha1_ctx *c, const unsigned char *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    uint32_t a = c->h[0], b = c->h[1], d = c->h[2], e = c->h[3], f = c->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t k, t;
        if (i < 20) {
            t = (b & d) | ((~b) & e);
            k = 0x5A827999;
        } else if (i < 40) {
            t = b ^ d ^ e;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            t = (b & d) | (b & e) | (d & e);
            k = 0x8F1BBCDC;
        } else {
            t = b ^ d ^ e;
            k = 0xCA62C1D6;
        }
        uint32_t tmp = rol(a, 5) + t + f + k + w[i];
        f = e; e = d; d = rol(b, 30); b = a; a = tmp;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += d; c->h[3] += e; c->h[4] += f;
}

void dropssh_sha1(const void *data, size_t len, unsigned char out[20]) {
    sha1_ctx c;
    c.h[0] = 0x67452301; c.h[1] = 0xEFCDAB89; c.h[2] = 0x98BADCFE;
    c.h[3] = 0x10325476; c.h[4] = 0xC3D2E1F0;
    c.len = 0; c.blen = 0;
    const unsigned char *p = data;
    c.len = (uint64_t)len * 8;
    while (len >= 64) {
        sha1_block(&c, p);
        p += 64;
        len -= 64;
    }
    unsigned char last[128];
    size_t n = len;
    memcpy(last, p, n);
    last[n++] = 0x80;
    while ((n % 64) != 56) {
        last[n++] = 0;
    }
    for (int i = 7; i >= 0; i--) {
        last[n++] = (unsigned char)((c.len >> (i * 8)) & 0xff);
    }
    for (size_t i = 0; i < n; i += 64) {
        sha1_block(&c, last + i);
    }
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (unsigned char)(c.h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c.h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c.h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(c.h[i]);
    }
}

void dropssh_ws_accept(const char *key, char *out, size_t outlen) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char buf[256];
    size_t kl = strlen(key);
    if (kl + sizeof guid > sizeof buf) {
        kl = sizeof buf - sizeof guid - 1;
    }
    memcpy(buf, key, kl);
    memcpy(buf + kl, guid, sizeof guid - 1);
    unsigned char d[20];
    dropssh_sha1(buf, kl + sizeof guid - 1, d);
    dropssh_b64_encode(d, 20, out, outlen);
}

void dropssh_sleep_ms(unsigned ms) {
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0) {
        /* interrupted; the remainder is in ts, so this resumes */
    }
}

unsigned dropssh_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (unsigned)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

/* --- egress settings, read once --- */
static char  proxy_host[256];
static int   proxy_port = 0;
static int   insecure = 0;
static int   loaded = 0;

static void load_settings(void) {
    if (loaded) {
        return;
    }
    loaded = 1;
    static const char *const keys[] = {
        "DROPSSH_PROXY", "https_proxy", "HTTPS_PROXY",
        "http_proxy", "HTTP_PROXY", NULL
    };
    for (int ki = 0; keys[ki] != NULL; ki++) {
        const char *p = getenv(keys[ki]);
        if (p && *p) {
            const char *h = strstr(p, "://");
            h = h ? h + 3 : p;
            size_t n = 0;
            while (h[n] && h[n] != '/' && n < sizeof proxy_host - 1) {
                proxy_host[n] = h[n];
                n++;
            }
            proxy_host[n] = 0;
            char *colon = strrchr(proxy_host, ':');
            if (colon) {
                *colon = 0;
                proxy_port = atoi(colon + 1);
            }
            if (proxy_port <= 0) {
                proxy_port = 8080;
            }
            if (proxy_host[0]) {
                return;
            }
        }
    }
    proxy_host[0] = 0;
    proxy_port = 0;
}

const char *dropssh_proxy_host(void) {
    load_settings();
    return proxy_host[0] ? proxy_host : NULL;
}

int dropssh_proxy_port(void) {
    load_settings();
    return proxy_port ? proxy_port : 8080;
}

int dropssh_insecure(void) { return insecure; }
void dropssh_set_insecure(int v) { insecure = v ? 1 : 0; }
