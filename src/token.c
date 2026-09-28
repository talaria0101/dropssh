/* token.c - token issuance and verification for `dropssh relay`.
 *
 * THE WIRE FORMAT, AND WHY IT IS THIS AND NOT A JWT
 * -------------------------------------------------
 *
 *     d1.<base64url(payload)>.<base64url(HMAC-SHA256(key, payload))>
 *
 * where the payload is `name|role|expires_ms`. Three dot-separated parts, no
 * header, no algorithm name, no signature type.
 *
 * ⛔ NO `alg` FIELD, AND THAT IS THE POINT. A JWT carries the algorithm it was
 * signed with IN the token, and a verifier that trusts that field accepts
 * `{"alg":"none"}` from anyone. The correct client behaviour is to ignore the
 * field and pin the algorithm itself, and the only way to guarantee a client
 * does that is for the format not to have the field at all. There is exactly
 * one algorithm here and it is not negotiable, so it is not on the wire.
 *
 * ⛔ NO BASE64 `=` PADDING, BECAUSE THE TOKEN IS A HEADER VALUE. A `=` in a
 * header is legal but a `+` and a `/` are the characters that have caused real
 * header-parsing bugs in proxies, and a token is a credential that will be
 * pasted into a command line by a person. base64url removes both and the
 * padding with them.
 *
 * ⛔ AND THE MAC IS OVER THE **DECODED** PAYLOAD BYTES. That is a deliberate
 * choice and the alternative was measured against: MAC over the base64 text on
 * the wire instead. It was tried first and it forces the verifier to
 * reconstruct the exact string the issuer built in order to check it, which
 * means a non-canonical base64 -- the same bytes with padding, or with a
 * different but equivalent case -- verifies differently on two relays that
 * minted from the same key. MAC over the decoded bytes means the MAC is a
 * property of the CLAIM, not of its spelling, so a token that survives a copy
 * through a paste buffer, a shell and a log line still verifies. The issuer and
 * the verifier then agree on one thing: the bytes of the claim.
 *
 * The `d1.` prefix is NOT covered by the MAC and does not need to be. It is a
 * constant, there is exactly one algorithm, and a constant cannot be varied by
 * an attacker; covering it would add a moving part and no security.
 *
 * A note on what a MAC is and is not: this authenticates the token, it does
 * not hide it. The name and the role are in cleartext inside the payload. That
 * is correct for this protocol, because the relay answers a node and an
 * operator on a name they both already know, and encrypting a field the peer
 * had to supply anyway would add a key schedule to defend nothing. The
 * credential is the MAC's unforgeability, not the payload's opacity.
 */
#include "token.h"
#include "util.h"

#include <mbedtls/md.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOKEN_PREFIX "d1."

/* ⛔ THE TOKEN IS BOUNDED AT EVERY LAYER, AND THE BOUNDS ARE NOT DECORATION.
 * A token arrives in an HTTP header from the network. `relay_token_from_header`
 * copies it into a fixed buffer and refuses anything longer, so a hostile
 * 64 KB header cannot make this code allocate. The parser below then works
 * only on that bounded buffer. Every length here is a compile-time constant
 * and the arithmetic is on `size_t` with an explicit bound check before the
 * loop, so there is no input for which an index leaves the buffer. */
#define TOKEN_MAX 512
#define B64URL_MAX (TOKEN_MAX * 2 + 4)

/* base64url, unpadded, for MAC input. ⛔ NOT the same encoder as
 * `dropssh_b64_encode`, and it must not be: that one emits `=` and `+` and
 * `/`, all three of which are wrong in a header value. */
static void b64url_encode(const unsigned char *in, size_t len, char *out,
                          size_t outlen) {
    static const char A[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < len && o + 4 < outlen; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < len) { v |= (unsigned)in[i + 1] << 8; }
        if (i + 2 < len) { v |= in[i + 2]; }
        out[o++] = A[(v >> 18) & 0x3f];
        out[o++] = A[(v >> 12) & 0x3f];
        if (i + 1 < len && o < outlen) { out[o++] = A[(v >> 6) & 0x3f]; }
        if (i + 2 < len && o < outlen) { out[o++] = A[v & 0x3f]; }
    }
    out[o] = 0;
}

static int b64url_val(char c) {
    if (c >= 'A' && c <= 'Z') { return c - 'A'; }
    if (c >= 'a' && c <= 'z') { return c - 'a' + 26; }
    if (c >= '0' && c <= '9') { return c - '0' + 52; }
    if (c == '-') { return 62; }
    if (c == '_') { return 63; }
    return -1;
}

/* ⛔ LENGTH-AWARE, AND THAT IS NOT A CONVENIENCE.
 *
 * The first version of this took a NUL-terminated string and stopped at the
 * terminator. It was then called on `body`, which is the whole rest of the
 * token -- payload, separator, MAC -- so the decoder ran on through the `.`
 * and returned -1, and a token this module had just issued did not verify.
 * The two call sites need different extents and a NUL-terminated interface
 * cannot express both without one of them copying into a buffer, which is an
 * allocation on a path whose whole point is that it cannot be made to
 * allocate. So the extent is an argument, and the callers pass what they mean.
 */
static int b64url_decode(const char *in, size_t inlen, unsigned char *out,
                         size_t outlen) {
    size_t o = 0;
    unsigned acc = 0;
    int bits = 0;
    for (size_t i = 0; i < inlen; i++) {
        if (in[i] == '=') {
            break;
        }
        int v = b64url_val(in[i]);
        if (v < 0) {
            return -1;
        }
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outlen) {
                return -1;
            }
            out[o++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    return (int)o;
}

void dropssh_key_from_passphrase(dropssh_key *k, const char *passphrase) {
    if (k == NULL) {
        return;
    }
    memset(k, 0, sizeof *k);
    if (passphrase == NULL || passphrase[0] == 0) {
        return;
    }
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == NULL) {
        /* ⛔ A BUILD WITH NO SHA-256 IS A BUILD THAT CANNOT ISSUE TOKENS, AND IT
         * SAYS SO BY BEING UNCONFIGURED rather than by hashing nothing. A key
         * of zeroes would verify every token. */
        return;
    }
    if (mbedtls_md(info, (const unsigned char *)passphrase,
                   strlen(passphrase), k->digest) != 0) {
        memset(k, 0, sizeof *k);
        return;
    }
    k->configured = 1;
}

int dropssh_key_configured(const dropssh_key *k) {
    return (k && k->configured) ? 1 : 0;
}

/* ⛔ THE MAC IS HMAC-SHA256 OVER THE PAYLOAD BYTES, AND THE KEY IS THE STORED
 * DIGEST. mbedcrypto's HMAC is used rather than a hand-rolled construction
 * because a home-grown one is exactly the kind of code that is correct in the
 * test vector and wrong in the field. */
static int mac_payload(const dropssh_key *k, const char *payload, size_t plen,
                       unsigned char out[32]) {
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == NULL) {
        return -1;
    }
    return mbedtls_md_hmac(info, k->digest, sizeof k->digest,
                           (const unsigned char *)payload, plen, out);
}

int dropssh_token_issue(const dropssh_key *k, const char *name,
                        dropssh_role role, long ttl_seconds,
                        long long now_ms, char *out, size_t outlen) {
    if (k == NULL || !k->configured || name == NULL || out == NULL) {
        return -1;
    }
    /* ⛔ THE NAME IS SANITISED AT ISSUE, NOT AT VERIFY. A name goes into the
     * payload delimited by `|`, and a name containing a `|` would let an
     * operator mint a token whose fields are not the fields the verifier
     * reads -- a token for name "a" and role node that verifies as name "a"
     * and role connect, if the parser splits differently from the issuer. The
     * separator is chosen once and the name is refused if it contains it. */
    if (name[0] == 0 || strchr(name, '|') != NULL || strchr(name, '\n') != NULL) {
        return -1;
    }
    if (strlen(name) >= 120) {
        return -1;
    }
    /* ⛔ A LIFETIME MUST BE POSITIVE, AND BOTH ENDS OF "NOT POSITIVE" ARE
     * REFUSED HERE RATHER THAN PRODUCING A TOKEN.
     *
     * A zero TTL issued a token that verified AT THE INSTANT OF ISSUE and not
     * one moment later: a credential with no lifetime, minted successfully, and
     * the first thing anybody noticed was that a session built on it died
     * without a message. A NEGATIVE TTL issued a token whose expiry was already
     * in the past, and the verifier then answered "malformed" for it -- a token
     * this relay had just signed, reported as not a token at all. Measured
     * 2026-09-28, both.
     *
     * The second is the worse of the two, and the reason is the same one that
     * runs through this file: a diagnostic that names the wrong fault costs an
     * afternoon. "expired" is the answer for a token whose time has passed, and
     * a token with a negative lifetime has had its time pass before it was
     * born. */
    if (ttl_seconds <= 0 || ttl_seconds > 10L * 365 * 24 * 3600) {
        return -1;
    }
    long long exp = now_ms + (long long)ttl_seconds * 1000;
    char payload[256];
    int pn = snprintf(payload, sizeof payload, "%s|%d|%lld", name,
                      (int)role, exp);
    if (pn <= 0 || (size_t)pn >= sizeof payload) {
        return -1;
    }
    unsigned char mac[32];
    if (mac_payload(k, payload, (size_t)pn, mac) != 0) {
        return -1;
    }
    char pb[B64URL_MAX], mb[B64URL_MAX];
    b64url_encode((const unsigned char *)payload, (size_t)pn, pb, sizeof pb);
    b64url_encode(mac, sizeof mac, mb, sizeof mb);
    int n = snprintf(out, outlen, "%s%s.%s", TOKEN_PREFIX, pb, mb);
    return (n > 0 && (size_t)n < outlen) ? 0 : -1;
}

/* ⛔ CONSTANT TIME, AND THE COMPARISON IS OVER A FIXED 32 BYTES SO ITS LENGTH
 * IS NOT A SIGNAL. A byte-by-byte `if (a[i] != b[i]) return 0;` returns
 * early and tells an attacker how many leading bytes were right, which is
 * enough to recover a MAC one byte at a time given enough attempts. */
static int mac_equal(const unsigned char *a, const unsigned char *b) {
    unsigned diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (unsigned)(a[i] ^ b[i]);
    }
    return diff == 0;
}

int dropssh_token_verify(const dropssh_key *k, const char *token,
                         dropssh_role want_role, long long now_ms,
                         dropssh_claims *out, const char **why) {
    if (out != NULL) {
        memset(out, 0, sizeof *out);
    }
    if (why != NULL) {
        *why = "malformed";
    }
    if (k == NULL || token == NULL || out == NULL) {
        return -1;
    }
    /* STEP 1: LENGTH, BEFORE ANY PARSING. ⛔ This is the bound that keeps a
     * hostile header out of the parser, and it is checked first so that a
     * 64 KB token costs one `strlen`. */
    size_t tl = strlen(token);
    if (tl <= sizeof TOKEN_PREFIX - 1 || tl >= TOKEN_MAX) {
        return -1;
    }
    if (memcmp(token, TOKEN_PREFIX, sizeof TOKEN_PREFIX - 1) != 0) {
        return -1;
    }
    const char *body = token + sizeof TOKEN_PREFIX - 1;
    const char *dot = strchr(body, '.');
    if (dot == NULL || dot == body) {
        return -1;
    }
    size_t plen = (size_t)(dot - body);
    const char *macb64 = dot + 1;
    if (macb64[0] == 0 || strchr(macb64, '.') != NULL) {
        return -1;
    }
    /* Decode the MAC and the payload. DECODING IS NOT BELIEVING: both writes
     * are into fixed buffers and both return -1 rather than growing, so a
     * hostile token cannot make this allocate. Nothing is ACTED on until the
     * MAC has been checked below. */
    unsigned char mac[32];
    int maclen = b64url_decode(macb64, strlen(macb64), mac, sizeof mac);
    if (maclen != 32) {
        return -1;
    }
    unsigned char payload[256];
    /* ⛔ THE PAYLOAD IS DECODED OVER ITS OWN EXTENT, `plen`, AND NOT OVER THE
     * REST OF THE TOKEN. Passing the tail instead is a bug that a token this
     * module issued reproduces every time, which is the whole reason it is
     * written as a comment. */
    int paylen = b64url_decode(body, plen, payload, sizeof payload - 1);
    if (paylen <= 0 || paylen >= (int)sizeof payload) {
        return -1;
    }
    payload[paylen] = 0;
    /* STEP 2: THE MAC, OVER THE CLAIM'S BYTES. */
    unsigned char want[32];
    if (mac_payload(k, (const char *)payload, (size_t)paylen, want) != 0) {
        return -1;
    }
    if (!mac_equal(mac, want)) {
        if (why != NULL) {
            *why = "bad-mac";
        }
        return -1;
    }
    /* STEP 3: AND ONLY NOW IS THE PAYLOAD DATA, because the MAC above proved
     * this key issued exactly these bytes. */
    char *first = strchr((char *)payload, '|');
    if (first == NULL) {
        return -1;
    }
    *first = 0;
    char *second = strchr(first + 1, '|');
    if (second == NULL) {
        return -1;
    }
    *second = 0;
    /* ⛔ THE NAME IS RE-CHECKED AT VERIFY AS WELL, even though the issuer
     * refuses a name with a separator. The MAC proves the payload came from
     * this key; it does not prove the payload is well formed, and a future
     * issuer that was less careful would otherwise be trusted implicitly. */
    if (payload[0] == 0 || strlen((char *)payload) >= sizeof out->name) {
        return -1;
    }
    if (first[1] == 0 || (first[1] != '0' && first[1] != '1')) {
        return -1;
    }
    dropssh_role role = (first[1] == '1') ? DROPSSH_ROLE_CONNECT
                                          : DROPSSH_ROLE_NODE;
    const char *digits = second + 1;
    if (digits[0] == 0) {
        return -1;
    }
    for (const char *p = digits; *p; p++) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
    }
    long long exp = strtoll(digits, NULL, 10);
    if (now_ms > 0 && exp > 0 && now_ms > exp) {
        if (why != NULL) {
            *why = "expired";
        }
        return -1;
    }
    if (role != want_role) {
        /* ⛔ A ROLE MISMATCH IS ITS OWN REASON AND NOT "bad-mac", because it is
         * the one of the four an operator can actually fix: the two tokens in
         * a pair are different and they are printed under different labels,
         * and swapping them is the mistake this reports. Saying "bad
         * signature" for a swapped pair is the least useful answer available. */
        if (why != NULL) {
            *why = "wrong-role";
        }
        return -1;
    }
    snprintf(out->name, sizeof out->name, "%s", (char *)payload);
    out->role = role;
    out->expires_ms = exp;
    if (why != NULL) {
        *why = "ok";
    }
    return 0;
}
