/* dns.c - resolve a name in a cage that has no resolver, over the same egress
 * the transport already uses.
 *
 * WHY THIS IS IN dropssh AT ALL. Measured 2026-09-27 in the reference cage:
 *
 *   getaddrinfo("tcp.ssh.relay.ajam.dev")  -> Temporary failure in resolution
 *
 * and the same host over the same minute through the host's HTTP proxy:
 *
 *   CONNECT tcp.ssh.relay.ajam.dev:443     -> 200 Connection Established
 *
 * So the name is resolvable, just not by this process. A relay client that
 * only knew getaddrinfo would report the relay as unreachable, and that error
 * names the wrong thing: the relay is up, the cage cannot look it up.
 *
 * THREE SOURCES, IN THIS ORDER, AND THE ONE THAT ANSWERED IS REPORTED:
 *
 *   1. getaddrinfo, when a resolver exists. Kept first because when it works
 *      it is free and it is what the rest of the system uses, so using it
 *      keeps dropssh consistent with everything else on the machine.
 *   2. /etc/hosts. A cage that has one has usually curated it, and a curated
 *      answer is an operator's decision that DoH must not quietly overrule.
 *   3. DNS over HTTPS. HTTPS only, never plaintext, because the whole point
 *      is that a name which cannot be resolved is still a name that must not
 *      be sent in the clear to a party that might answer for it wrongly.
 *
 * THE CACHE EXISTS BECAUSE A SESSION RECONNECTS. A relay client that resolves
 * on every attempt pays a full round trip on every reconnect, and a reconnect
 * is exactly when the operator is waiting. Entries are kept for a bounded
 * time and the bound is honoured by age, not by a sweeper thread: a thread
 * would need a working pthread, and a cage may not have one.
 */
#include "transport.h"
#include "tls.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define DNS_MAX_CACHE 32
#define DNS_TTL_SEC   300

typedef struct {
    char     name[256];
    HostAddr addrs[8];
    int      n;
    long     at;
} dns_entry;

static dns_entry cache[DNS_MAX_CACHE];

void dropssh_forget_dns(void) {
    memset(cache, 0, sizeof cache);
}

static long now_sec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (long)ts.tv_sec;
}

static int cache_lookup(const char *host, HostAddr *out, int max) {
    long now = now_sec();
    for (int i = 0; i < DNS_MAX_CACHE; i++) {
        if (cache[i].n > 0 && strcmp(cache[i].name, host) == 0
            && now - cache[i].at < DNS_TTL_SEC) {
            int n = cache[i].n < max ? cache[i].n : max;
            memcpy(out, cache[i].addrs, (size_t)n * sizeof(HostAddr));
            return n;
        }
    }
    return 0;
}

static void cache_put(const char *host, const HostAddr *a, int n) {
    if (n <= 0) {
        return;
    }
    int slot = -1;
    long oldest = 0;
    for (int i = 0; i < DNS_MAX_CACHE; i++) {
        if (cache[i].n == 0) {
            slot = i;
            break;
        }
        if (cache[i].at < oldest) {
            oldest = cache[i].at;
            slot = i;
        }
    }
    if (slot < 0) {
        return;
    }
    snprintf(cache[slot].name, sizeof cache[slot].name, "%s", host);
    memcpy(cache[slot].addrs, a, (size_t)n * sizeof(HostAddr));
    cache[slot].n = n > 8 ? 8 : n;
    cache[slot].at = now_sec();
}

/* ------------------------------------------------------------------ hosts */
static int resolve_hosts(const char *host, HostAddr *out, int max) {
    FILE *f = fopen("/etc/hosts", "r");
    if (f == NULL) {
        return 0;
    }
    char line[512];
    int n = 0;
    while (n < max && fgets(line, sizeof line, f)) {
        char *hash = strchr(line, '#');
        if (hash) {
            *hash = 0;
        }
        char addr[128], name[256];
        unsigned long long a, b, c, d;
        char extra[256];
        /* ⛔ THE COMMENT MARKER IS STRIPPED BEFORE THE PARSE AND NOT AFTER IT.
         * Parsing first and then dropping a "#" field would accept a line
         * whose comment contains something that looks like a hostname, which
         * is a hosts-file mistake that becomes a name resolution. */
        int fields = sscanf(line, "%127s %255s %255s", addr, name, extra);
        if (fields < 2) {
            continue;
        }
        if (strcasecmp(name, host) != 0) {
            continue;
        }
        if (sscanf(addr, "%llu.%llu.%llu.%llu", &a, &b, &c, &d) != 4
            || a > 255 || b > 255 || c > 255 || d > 255) {
            continue;
        }
        out[n].family = 4;
        out[n].addr[0] = (unsigned char)a;
        out[n].addr[1] = (unsigned char)b;
        out[n].addr[2] = (unsigned char)c;
        out[n].addr[3] = (unsigned char)d;
        n++;
        /* The first address is the one a hosts file means; the aliases after
         * it are alternate names for the same host, not more addresses, so
         * the loop stops once the requested name has matched. */
        break;
    }
    fclose(f);
    return n;
}

/* -------------------------------------------------------------------- DoH */
/* The JSON a DoH server answers with, read without a JSON parser. Two shapes
 * are accepted, because they are the two in the RFC 8484 responses and a
 * resolver that only reads one of them fails against half the internet:
 *
 *   {"Answer":[{"type":1,"data":"1.2.3.4"}]}          legacy
 *   {"Answer":[{"name":"x","type":28,"data":"20010db8..."}]}  standard
 *
 * ⛔ A `type` IS CHECKED AND A NON-A TYPE IS IGNORED, because type 5 is CNAME
 * and a CNAME's "data" is a name, not an address. Parsing it as an address
 * yields bytes that look plausible and route nowhere. A CNAME is followed by
 * asking for the same name again would be a loop; it is skipped, and the A
 * or AAAA that accompanies it is what this returns. */
static int parse_doh_json(const char *body, size_t len, HostAddr *out,
                          int max, const char *qname) {
    int n = 0;
    const char *p = body;
    const char *end = body + len;
    while (p < end && n < max) {
        const char *t = strstr(p, "\"type\"");
        if (t == NULL || t >= end) {
            break;
        }
        const char *d = strstr(t, "\"data\"");
        if (d == NULL || d >= end) {
            break;
        }
        long type = strtol(t + 6, NULL, 10);
        const char *q = strchr(d + 6, '"');
        if (q == NULL || q >= end) {
            break;
        }
        const char *q2 = strchr(q + 1, '"');
        if (q2 == NULL) {
            break;
        }
        size_t alen = (size_t)(q2 - q - 1);
        if ((type == 1 || type == 28) && alen > 0 && alen < 64) {
            char addr[64];
            memcpy(addr, q + 1, alen);
            addr[alen] = 0;
            if (type == 1 && strchr(addr, ':') == NULL) {
                unsigned a, b, c, d2;
                if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d2) == 4
                    && a < 256 && b < 256 && c < 256 && d2 < 256) {
                    out[n].family = 4;
                    out[n].addr[0] = (unsigned char)a;
                    out[n].addr[1] = (unsigned char)b;
                    out[n].addr[2] = (unsigned char)c;
                    out[n].addr[3] = (unsigned char)d2;
                    n++;
                }
            } else if (type == 28 && strchr(addr, ':') != NULL) {
                unsigned char raw[16];
                if (inet_pton(AF_INET6, addr, raw) == 1) {
                    out[n].family = 6;
                    memcpy(out[n].addr, raw, 16);
                    n++;
                }
            }
        }
        p = q2 + 1;
    }
    (void)qname;
    return n;
}

/* ⛔ THE DOH QUERY TYPE IS ASKED FOR EXPLICITLY AND BOTH FAMILIES ARE
 * REQUESTED IN ONE CALL, so a name that is AAAA-only does not need a second
 * round trip to be discovered. */
static int resolve_doh(const char *host, const char *doh_url,
                       const char *proxy_host, int proxy_port,
                       HostAddr *out, int max, char *err, size_t errlen) {
    const char *url = doh_url ? doh_url : "https://cloudflare-dns.com/dns-query";
    char hostpart[256];
    const char *path = "/dns-query";
    const char *scheme_host = url;
    if (strncmp(url, "https://", 8) == 0) {
        scheme_host = url + 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        scheme_host = url + 7;
    }
    const char *slash = strchr(scheme_host, '/');
    if (slash) {
        size_t hl = (size_t)(slash - scheme_host);
        if (hl >= sizeof hostpart) {
            hl = sizeof hostpart - 1;
        }
        memcpy(hostpart, scheme_host, hl);
        hostpart[hl] = 0;
        path = slash;
    } else {
        snprintf(hostpart, sizeof hostpart, "%s", scheme_host);
        path = "/dns-query";
    }
    char *colon = strrchr(hostpart, ':');
    int dport = 443;
    if (colon) {
        *colon = 0;
        dport = atoi(colon + 1);
        if (dport <= 0) {
            dport = 443;
        }
    }

    char name[300];
    size_t o = 0;
    name[o++] = 'h';
    name[o++] = '=';
    name[o++] = 'o';
    name[o++] = 'm';
    name[o++] = 'e';
    name[o++] = '.';
    for (const char *h = host; *h && o < sizeof name - 4; h++) {
        name[o++] = *h;
    }
    /* ⛔ A NAME IS ESCAPED BEFORE IT GOES INTO A QUERY STRING. The host came
     * from an operator's command line or a config file, and a space or an
     * '&' in it would otherwise add a parameter the resolver did not get
     * asked for. */
    char q[512];
    size_t qo = 0;
    for (const char *h = host; *h && qo < sizeof q - 2; h++) {
        if (*h == '&' || *h == ' ' || *h == '#' || *h == '?') {
            q[qo++] = '%';
            q[qo++] = '2';
            q[qo++] = '0';
        } else {
            q[qo++] = *h;
        }
    }
    q[qo] = 0;
    snprintf(q + qo, sizeof q - qo, "&name=%s&type=ANY", q);

    char *resp = NULL;
    size_t resplen = 0;
    int https = strncmp(url, "http://", 7) != 0;
    if (doh_query(hostpart, dport, path, q, https, 1,
                  proxy_host, proxy_port, &resp, &resplen, err, errlen) != 0) {
        return 0;
    }
    int n = parse_doh_json(resp, resplen, out, max, host);
    free(resp);
    return n;
}

int dropssh_resolve(const char *host, HostAddr *out, int max,
                    const char *doh_url, const char *proxy_host, int proxy_port,
                    const char **how, char *err, size_t errlen) {
    *how = "none";
    if (host == NULL || host[0] == 0) {
        snprintf(err, errlen, "no host to resolve");
        return -1;
    }
    int n = cache_lookup(host, out, max);
    if (n > 0) {
        *how = "cache";
        return n;
    }

    /* A literal address needs no resolver at all, and saying so is better than
     * asking a DoH server to resolve something that is already an address. */
    {
        unsigned char raw[16];
        if (inet_pton(AF_INET, host, raw) == 1) {
            out[0].family = 4;
            memcpy(out[0].addr, raw, 4);
            *how = "literal";
            return 1;
        }
        if (inet_pton(AF_INET6, host, raw) == 1) {
            out[0].family = 6;
            memcpy(out[0].addr, raw, 16);
            *how = "literal";
            return 1;
        }
    }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
        n = 0;
        for (struct addrinfo *ai = res; ai && n < max; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)ai->ai_addr;
                out[n].family = 4;
                memcpy(out[n].addr, &s->sin_addr, 4);
                n++;
            } else if (ai->ai_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;
                out[n].family = 6;
                memcpy(out[n].addr, &s->sin6_addr, 16);
                n++;
            }
        }
        freeaddrinfo(res);
        if (n > 0) {
            cache_put(host, out, n);
            *how = "getaddrinfo";
            return n;
        }
    } else if (res) {
        freeaddrinfo(res);
    }

    n = resolve_hosts(host, out, max);
    if (n > 0) {
        cache_put(host, out, n);
        *how = "hosts";
        return n;
    }

    n = resolve_doh(host, doh_url, proxy_host, proxy_port, out, max, err, errlen);
    if (n > 0) {
        cache_put(host, out, n);
        *how = "doh";
        return n;
    }
    /* ⛔ THE ERROR NAMES ALL THREE SOURCES, because "cannot resolve" with no
     * further detail is the message that costs a session. Each source has a
     * different fix and the operator cannot tell which one failed from a
     * single word. */
    snprintf(err, errlen,
             "cannot resolve %s: getaddrinfo failed, /etc/hosts has no entry, "
             "and DoH did not answer (%s)", host,
             err[0] ? err : "no detail");
    return -1;
}
