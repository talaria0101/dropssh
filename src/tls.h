/* tls.h - the one place dropssh touches a TLS implementation.
 *
 * WHY THIS IS AN ADAPTER AND NOT A STACK. Measured 2026-09-27: the relay
 * negotiates TLS 1.3 with X25519MLKEM768, a post-quantum hybrid, and this
 * cage has no OpenSSL, no mbedtls, no wolfSSL, no gnutls, not even a static
 * archive. Writing a TLS 1.3 client here would mean X25519, AES-GCM, SHA-384,
 * HKDF, transcript hashing, a certificate parser and a trust store, added to
 * a program whose purpose is to be an ssh server, in exchange for not
 * vendoring a dependency. The reasoning in full is in
 * docs/decisions-tls.md.
 *
 * SO THE IMPLEMENTATION IS A BUILD INPUT, CHOSEN AT COMPILE TIME, AND
 * RECORDED IN BUILDINFO. A binary built here says which one it carries
 * rather than leaving a reader to guess from the absence of a symbol.
 *
 * ⛔ VERIFICATION IS ON BY DEFAULT AND `--insecure` IS THE ONLY WAY PAST IT.
 * A relay client that skips verification by default is a client whose
 * ssh session is only as private as the path to the relay, and the operator
 * is the one who can decide that. The insecure path is exercised by its own
 * negative test so it is known to work and known to be reachable only on
 * purpose.
 */
#ifndef DROPSSH_TLS_H
#define DROPSSH_TLS_H

#include <stddef.h>

#include "transport.h"

/* Which TLS implementation this binary was linked against. "libcurl" or
 * "mbedtls". Recorded in BUILDINFO and printed by `dropssh --version`, because
 * a binary that cannot name its own TLS is a binary nobody can triage. */
const char *dropssh_tls_backend(void);

/* Wrap `tcp` in TLS. `sni` is the server name to verify and send; NULL uses
 * the name the transport was opened with. Returns a Transport that owns
 * `tcp`, on success or on failure, so there is one close path. */
Transport *transport_tls(Transport *tcp, const char *sni, int insecure,
                         char *err, size_t errlen);

/* One HTTPS GET, returning the body in `*body` (malloc'd, NUL-terminated, and
 * `*len` excludes the terminator). Used by the DoH resolver and the token
 * mint, so both go over the same egress, with the same proxy, and with the
 * same verification policy as the websocket they are setting up. */
int tls_get(const char *host, int port, const char *path, const char *query,
            int https, int insecure, const char *proxy_host, int proxy_port,
            const char **resp_headers,
            char **body, size_t *len, char *err, size_t errlen);

/* One HTTPS POST with a body, for the relay's self-service token endpoint. */
int tls_post(const char *host, int port, const char *path, const char *body,
             int https, int insecure, const char *proxy_host, int proxy_port,
             char **resp, size_t *len, char *err, size_t errlen);

/* The last TLS failure in words, or NULL. Set when a handshake or a read
 * fails, so a caller can say WHY a relay was unreachable instead of reporting
 * a closed socket for a certificate that did not verify. */
const char *dropssh_tls_lasterror(void);

/* Internal name used by dns.c; the DoH path is a GET with a pinned name. */
int doh_query(const char *host, int port, const char *path, const char *query,
              int https, int insecure, const char *proxy_host, int proxy_port,
              char **body, size_t *len, char *err, size_t errlen);

#endif /* DROPSSH_TLS_H */
