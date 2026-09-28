/* token-test.c - the bearer-token contract, on the real token.c.
 *
 * ⛔ WHY A TOKEN NEEDS A TEST OF ITS OWN, AND IT IS NOT A UNIT TEST FOR THE
 * SAKE OF ONE.
 *
 * A signer with no verifier is the classic half-built: the code that issues is
 * written, shipped, and looks right, and the code that checks is written later
 * against a different idea of the format. This file exists so that the two are
 * the same function's two ends, and the negative cases are the ones that
 * matter: a token from the WRONG KEY, a token for the WRONG ROLE, an EXPIRED
 * token, a token whose payload has been edited, and a token that is only a
 * prefix of a real one. A suite that only checks "the happy path round-trips"
 * has established that the encoder and decoder share a bug, which is the most
 * likely way for both to be wrong together.
 *
 * ⛔ AND THE ROLE SEPARATION IS TESTED AS ITS OWN THING, because that is the
 * control. Issue #13's ladder depends on a pair issued by our relay working
 * against it, and a pair is two DIFFERENT credentials. If the verifier accepts
 * a node token where an operator token belongs, then anyone who can read the
 * node's token -- which appears in the cage, in a config file, in a log line --
 * can open a session. So the test asserts that the node token is REFUSED on
 * the operator's path, with a reason an operator can act on.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/token.h"
#include "../src/util.h"

static int pass = 0, fail = 0;
static void ok(const char *what)  { printf("  ok    %s\n", what); pass++; }

/* ⛔ VARIADIC, BECAUSE EVERY NEGATIVE CASE HERE NAMES WHAT IT WAS REFUSED FOR.
 * A fixed-argument `bad()` would force each of those to be formatted into a
 * buffer first, and a reader would then have to tell a formatted sentence from
 * a literal one. More to the point, it would be easy to write `bad("...")`
 * with a `%s` in it and no argument, which prints a literal `%s` and looks
 * like a passing run. Making the formatter the only way in removes that. */
#include <stdarg.h>
static void bad(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("  FAIL  ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    fail++;
}

#define KEY_A "correct horse battery staple, relay 1"
#define KEY_B "a different key entirely, relay 2"

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    long long now = 1700000000000LL;   /* fixed, so expiry is not wall-clock */

    dropssh_key ka, kb;
    dropssh_key_from_passphrase(&ka, KEY_A);
    dropssh_key_from_passphrase(&kb, KEY_B);

    printf("== the bearer-token contract, on the real token.c\n");

    /* ---- an unconfigured key is a VALID state meaning "accept anything" */
    {
        dropssh_key none;
        dropssh_key_from_passphrase(&none, NULL);
        if (dropssh_key_configured(&none)) {
            bad("a key built from a NULL passphrase reports itself configured");
        } else {
            dropssh_key empty;
            dropssh_key_from_passphrase(&empty, "");
            if (dropssh_key_configured(&empty)) {
                bad("a key built from an empty passphrase reports itself configured");
            } else {
                ok("an unset key is unconfigured, and that means 'no verification'");
            }
        }
        char t[600];
        if (dropssh_token_issue(&none, "n", DROPSSH_ROLE_NODE, 60, now,
                                t, sizeof t) == 0) {
            bad("a token was issued by a relay with no key");
        } else {
            ok("a relay with no key issues nothing, rather than a token nobody can verify");
        }
    }

    if (!dropssh_key_configured(&ka)) {
        bad("key A did not configure; every other case here is meaningless");
        printf("== %d passed, %d failed\n", pass, fail);
        return 1;
    }

    char node_tok[600], conn_tok[600];
    if (dropssh_token_issue(&ka, "box", DROPSSH_ROLE_NODE, 3600, now,
                            node_tok, sizeof node_tok) != 0) {
        bad("issuing a node token failed");
        printf("== %d passed, %d failed\n", pass, fail);
        return 1;
    }
    dropssh_token_issue(&ka, "box", DROPSSH_ROLE_CONNECT, 3600, now,
                        conn_tok, sizeof conn_tok);
    if (conn_tok[0] == 0 || strcmp(node_tok, conn_tok) == 0) {
        bad("the two roles produced the same token, so the tokens carry no role");
    } else {
        ok("a node token and a connect token for the same name differ");
    }

    /* ---- 1. the round trip, which is the only case that proves nothing on
     * its own and is here so a later failure has a control */
    {
        dropssh_claims c;
        const char *why = "";
        if (dropssh_token_verify(&ka, node_tok, DROPSSH_ROLE_NODE, now,
                                 &c, &why) != 0) {
            bad("a freshly issued node token did not verify: %s", why);
        } else if (strcmp(c.name, "box") != 0) {
            bad("the verified name is %s, expected box", c.name);
        } else {
            ok("a node token verifies on the node's role and carries its name");
        }
    }

    /* ---- 2. ROLE SEPARATION. A node token must NOT open an operator's path. */
    {
        dropssh_claims c;
        const char *why = "";
        if (dropssh_token_verify(&ka, node_tok, DROPSSH_ROLE_CONNECT, now,
                                 &c, &why) == 0) {
            bad("a node token was accepted where a connect token belongs: the "
                "two roles are not separated, so reading the cage's token is "
                "enough to open a session");
        } else if (strcmp(why, "wrong-role") != 0) {
            bad("a node token on the connect path was refused with '%s', "
                "expected 'wrong-role' so the operator can tell a swap from a "
                "bad key", why);
        } else {
            ok("a node token is refused on the connect path, and says why");
        }
    }

    /* ---- 3. THE WRONG KEY. A pair from one relay must not open another
     * relay that holds a different key. */
    {
        dropssh_claims c;
        const char *why = "";
        if (dropssh_token_verify(&kb, node_tok, DROPSSH_ROLE_NODE, now,
                                 &c, &why) == 0) {
            bad("a token from key A verified against key B");
        } else if (strcmp(why, "bad-mac") != 0) {
            bad("a token from the wrong key was refused with '%s', expected "
                "'bad-mac'", why);
        } else {
            ok("a token from a different key is refused as bad-mac");
        }
    }

    /* ---- 4. TAMPERING. Flipping a byte of the MAC must fail. */
    {
        char t[600];
        snprintf(t, sizeof t, "%s", node_tok);
        size_t n = strlen(t);
        /* the last non-punctuation character of the MAC */
        for (size_t i = n - 1; i > 0; i--) {
            if (t[i] == '.') { break; }
            if (t[i] == 'A') { t[i] = 'B'; } else { t[i] = 'A'; }
            break;
        }
        dropssh_claims c;
        const char *why = "";
        if (dropssh_token_verify(&ka, t, DROPSSH_ROLE_NODE, now, &c, &why) == 0) {
            bad("a token with one byte of its MAC changed still verified");
        } else {
            ok("a token with one changed MAC byte does not verify");
        }
    }

    /* ---- 5. EXPIRY, AND IT IS THE ONLY TIME DEPENDENCE IN THE FILE. The
     * clock is passed in, so this cannot go flaky at midnight or on a slow
     * runner, which is the reason the API takes now_ms at all. */
    {
        char t[600];
        dropssh_token_issue(&ka, "box", DROPSSH_ROLE_NODE, 10, now, t, sizeof t);
        dropssh_claims c;
        const char *why = "";
        if (dropssh_token_verify(&ka, t, DROPSSH_ROLE_NODE, now + 5000, &c, &why) != 0) {
            bad("a 10-second token was refused after 5 seconds");
        } else {
            ok("a token is good before its expiry");
        }
        if (dropssh_token_verify(&ka, t, DROPSSH_ROLE_NODE, now + 60000, &c, &why) == 0) {
            bad("a 10-second token was accepted after 60 seconds");
        } else if (strcmp(why, "expired") != 0) {
            bad("an expired token was refused with '%s', expected 'expired'", why);
        } else {
            ok("a token is refused after its expiry, and says so");
        }
    }

    /* ---- 6. A NAME WITH THE SEPARATOR IN IT IS REFUSED AT ISSUE, because
     * that is the one place a name can smuggle a field boundary. */
    {
        char t[600];
        if (dropssh_token_issue(&ka, "a|1|999", DROPSSH_ROLE_NODE, 60, now,
                                t, sizeof t) == 0) {
            bad("a name containing the field separator was issued as a token");
        } else {
            ok("a name containing the field separator is refused at issue");
        }
    }

    /* ---- 7. A MALFORMED TOKEN IS REFUSED, AND THE HOSTILE LENGTH IS THE
     * ONE THAT MATTERS. A verifier that parses before it bounds is a parser
     * with a network feeding it. */
    {
        dropssh_claims c;
        const char *why = "";
        char big[4096];
        memset(big, 'A', sizeof big - 1);
        big[sizeof big - 1] = 0;
        if (dropssh_token_verify(&ka, big, DROPSSH_ROLE_NODE, now, &c, &why) == 0) {
            bad("a 4 KB token of A's verified");
        } else if (dropssh_token_verify(&ka, "", DROPSSH_ROLE_NODE, now, &c, &why) == 0
                   || dropssh_token_verify(&ka, "d1.", DROPSSH_ROLE_NODE, now, &c, &why) == 0
                   || dropssh_token_verify(&ka, "d1..", DROPSSH_ROLE_NODE, now, &c, &why) == 0
                   || dropssh_token_verify(&ka, "d2.abc.def", DROPSSH_ROLE_NODE, now, &c, &why) == 0
                   || dropssh_token_verify(&ka, "not a token at all", DROPSSH_ROLE_NODE, now, &c, &why) == 0) {
            bad("one of the empty/short/wrong-prefix forms verified");
        } else {
            ok("empty, short, wrong-prefix and 4 KB tokens are all refused");
        }
    }

    printf("== %d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
