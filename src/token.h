/* token.h - token issuance and verification for `dropssh relay`.
 *
 * ⛔ WHY THIS EXISTS, AND IT IS ISSUE #13 STEP 1.
 *
 * `dropssh relay` speaks the ajam relay's protocol perfectly and issues no
 * credentials at all. So a pair created by the ajam relay's `POST /v1/pair`
 * cannot be replayed against ours, which means the ladder in #13 stops at step
 * one: "use our own relay" is a sentence, not a route, because a node and an
 * operator both arrive with a token ours cannot check. `dropssh_request_pair`
 * in `ws.c` already parses `{name, node_token, connect_token, stop_token,
 * expires}` out of an HTTP POST, and `dropssh pair` already prints them, so
 * the only thing missing was a signer on our side.
 *
 * THE WIRE FORMAT
 * ---------------
 *
 *     d1.<base64url(name|role|expires_ms)>.<base64url(HMAC-SHA256(key, payload))>
 *
 * Three dot-separated parts, no header, no algorithm name, no signature type,
 * and the MAC is over the **decoded** payload rather than over its base64
 * spelling. ⛔ No `alg` field, because a JWT carries the algorithm it was
 * signed with IN the token and a verifier that trusts that field accepts
 * `{"alg":"none"}` from anyone. There is exactly one algorithm here and it is
 * not negotiable, so it is not on the wire. ⛔ No base64 `=` padding, and
 * `base64url` rather than standard base64, because a token is a header value
 * and a credential pasted into a command line, and `+`, `/` and `=` are the
 * three characters that cause real header-parsing and copy-paste failures.
 *
 * A note on what a MAC is and is not: this authenticates the token, it does
 * not hide it. The name and the role are in cleartext inside the payload, and
 * that is correct here, because the relay answers a node and an operator on a
 * name they both already supplied. The credential is the MAC's unforgeability,
 * not the payload's opacity, and claiming otherwise would be a comment some
 * later reader relies on to justify not checking it.
 *
 * ⛔ AND THE SHAPE IS CHOSEN SO A PAIR IS PORTABLE, WHICH IS THE WHOLE POINT.
 * A token is a bearer credential: it carries its own name, its own role and
 * its own expiry, and it is authenticated by a MAC over exactly those fields.
 * It is not a handle into a table on the relay that issued it. That is what
 * lets a node and an operator pair against OUR relay and then be moved to
 * another relay of ours, or back to the ajam relay, **without being
 * re-created** -- which is the second line of #13's definition of done. A
 * server-side session table would make every token single-relay and the
 * migration impossible by construction.
 *
 * ⛔ THE CONSEQUENCE, AND IT IS THE ONE THAT MATTERS: A RELAY THAT DOES NOT
 * HOLD THE KEY WILL NOT HONOUR ANYTHING. Token verification is OPTIONAL on a
 * relay, and a relay with no key configured accepts every token. That is not a
 * convenience, it is the backwards-compatibility rule, and it is why a
 * deployment that wants role separation has to be told to set a key. A relay
 * that silently accepted everything while claiming to verify would be the
 * worst of both, so `dropssh relay --print-status` says whether this process
 * is checking or ignoring.
 */
#ifndef DROPSSH_TOKEN_H
#define DROPSSH_TOKEN_H

#include <stddef.h>

/* The two roles. A node registers and an operator connects, and they are
 * different credentials: `dropssh pair` prints them under different labels and
 * swapping them produces a 403 that says "no token, or the wrong token" and
 * not "you swapped them", which is the hardest version of that fault to
 * diagnose. */
typedef enum {
    DROPSSH_ROLE_NODE = 0,
    DROPSSH_ROLE_CONNECT = 1
} dropssh_role;

/* ⛔ A HASHED KEY, NOT THE KEY, AND THE REASON IS WHERE THE KEY LIVES.
 *
 * The key is a passphrase, because a human has to type it into a relay's
 * command line or environment on whatever host is running the relay. Storing
 * it raw would mean the verifier and the verifier's memory layout are the
 * thing an operator has to protect, and the relay holds the key for its whole
 * life. Storing SHA-256 of it means the live secret exists only in the
 * operator's configuration and in whatever they typed, and a dump of this
 * process's memory yields something that cannot mint a pair. The MAC is then
 * computed FROM the stored hash, so the hash is the working key and there is
 * no point at which the raw passphrase is needed again.
 *
 * ⛔ AND SHA-256 IS HERE BECAUSE IT IS THE PRIMITIVE, NOT INSTEAD OF IT: the
 * token's integrity is HMAC-SHA256 from mbedcrypto, which is already linked
 * for TLS. `util.c` has SHA-1 and its comment says outright that it is not for
 * anything needing collision resistance, and this is a credential. */
typedef struct {
    unsigned char digest[32];  /* SHA-256 of the key; all-zero means "no key" */
    int           configured;
} dropssh_key;

/* ⛔ AN UNCONFIGURED KEY IS A VALID STATE AND IT MEANS "ACCEPT ANYTHING".
 * This is deliberate and it is the compatibility rule: `dropssh relay` today
 * takes no token, serves every session, and a change that made it refuse
 * unconfigured peers would break every existing deployment on the first
 * upgrade. So a relay without a key behaves exactly as it did, and
 * `dropssh relay --print-status` and the startup banner both say so. */
void dropssh_key_from_passphrase(dropssh_key *k, const char *passphrase);
int  dropssh_key_configured(const dropssh_key *k);

/* Issue a token for `name` in `role`, valid for `ttl_seconds`.
 * Returns 0 on success and writes at most `outlen` bytes. */
int dropssh_token_issue(const dropssh_key *k, const char *name,
                        dropssh_role role, long ttl_seconds,
                        long long now_ms, char *out, size_t outlen);

/* Verify a token.
 *
 * ⛔ THE ORDER OF THE CHECKS IS THE SECURITY, AND IT IS WRITTEN DOWN BECAUSE
 * THE OBVIOUS ORDER IS THE WRONG ONE. A naive verifier compares the MAC first
 * and is done, which is right; a naive verifier that parses first and
 * validates length as it goes will happily report WHICH field was wrong, and
 * that turns the token parser into an oracle for a forgery attempt. So:
 *
 *   1. reject on LENGTH before reading anything, so a hostile 8 KB header
 *      cannot make this allocate or loop;
 *   2. recompute the MAC over the payload as RECEIVED and compare in constant
 *      time, so a wrong token is refused without saying which byte was wrong
 *      and without an early-exit timing signal;
 *   3. only then parse the name, the role and the expiry, which by this point
 *      is data this process just proved it minted.
 *
 * A token signed by another key is refused at step 2 with the same answer as a
 * token that was never signed, so an attacker learns nothing about which pairs
 * exist. */
typedef struct {
    char        name[128];
    dropssh_role role;
    long long   expires_ms;
} dropssh_claims;

/* Returns 0 when the token is good and fills `out`. Returns non-zero
 * otherwise and leaves `out` zeroed. `why` gets a short machine-ish reason for
 * the relay's log: "malformed", "bad-mac", "expired", "wrong-role". */
int dropssh_token_verify(const dropssh_key *k, const char *token,
                         dropssh_role want_role, long long now_ms,
                         dropssh_claims *out, const char **why);

#endif /* DROPSSH_TOKEN_H */
