/* socks-policy-test.c - the SOCKS5 POLICY, which is the security, on the real
 * relay's own decision function.
 *
 * ⛔ WHY THIS IS A UNIT TEST AND NOT A CASE IN mux-probe.py.
 *
 * The SOCKS listener binds an INET socket, and dropssh#6 measured 24/24 that
 * every INET bind is refused with EACCES at uid 0. So on the machine this
 * project is developed and tested on, the listener cannot be started at all
 * and no probe case can drive it. That is not a reason to ship the policy
 * unasserted: it is a reason to assert the DECISION where it can be reached.
 *
 * The decision is one function and one question -- "is this destination the
 * one the operator named?" -- and it is the whole reason the feature is not an
 * open proxy. Everything else about SOCKS5 is protocol, and the protocol is
 * either implemented or it is not; this is a judgement, and judgements are what
 * go wrong quietly.
 *
 * ⛔ AND THE CASES THAT MATTER ARE THE REFUSALS. A proxy that dials whatever it
 * is asked to dial is an open proxy the moment it is reachable, and this one is
 * reachable by everything that can reach the operator. A test that only checks
 * "the named destination is allowed" would pass on a function that allowed
 * everything, which is the defect.
 *
 * The function is `static` in `relay.c`, so this file includes the translation
 * unit's decision function's source by way of a small shim rather than
 * re-implementing it: a test that re-implements the policy tests the test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* ⛔ THE FUNCTION UNDER TEST IS `#include`d FROM A FILE EXTRACTED OUT OF
 * src/relay.c BY tests/socks-policy-test.sh, NOT COPIED HERE.
 *
 * A test that copies the policy asserts the copy. This one compiles the
 * shipping function, so a change to the product that the test has not seen is
 * a test that fails to build rather than a test that has been quietly
 * asserting something else since the day somebody edited it. The extraction
 * also supplies the two settings the policy reads, so there is one
 * declaration of them in the whole build. */
#include "socks_policy_gen.h"

static int pass = 0, fail = 0;
static void ok(const char *what)  { printf("  ok    %s\n", what); pass++; }
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

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("== the SOCKS5 destination policy, on the real relay's own function\n");

    /* ---- 1. the named destination is allowed, in every form a client may
     * send it. A proxy that refuses its own configured destination is a proxy
     * that does not work, and the first version of a strict comparison broke
     * exactly here: a domain is compared as TEXT and a dotted quad as BYTES,
     * and doing it the other way round refuses the case an operator named. */
    {
        struct in_addr a;
        inet_pton(AF_INET, "10.0.0.5", &a);
        snprintf(socks_host, sizeof socks_host, "10.0.0.5");
        socks_port = 8080;
        unsigned char v4[4];
        memcpy(v4, &a, 4);
        if (!socks_destination_allowed(0x01, v4, 8080)) {
            bad("the destination the operator NAMED was refused when sent as "
                "the dotted quad it was named as");
        } else {
            ok("a dotted-quad destination the operator named is allowed");
        }
    }
    {
        unsigned char dom[1 + 15];
        dom[0] = 15;
        memcpy(dom + 1, "target.internal", 15);
        snprintf(socks_host, sizeof socks_host, "target.internal");
        socks_port = 443;
        if (!socks_destination_allowed(0x03, dom, 443)) {
            bad("a domain destination the operator named was refused");
        } else {
            ok("a domain destination the operator named is allowed");
        }
    }
    {
        /* ⛔ AND A DOMAIN IS COMPARED CASE-INSENSITIVELY, because a name is not
         * an address. `Target.Internal` and `target.internal` are the same
         * host and a case-sensitive comparison would refuse one of them, which
         * reads as "the proxy works but is broken" and is the sort of thing an
         * operator debugs for an afternoon. */
        unsigned char dom[1 + 15];
        dom[0] = 15;
        memcpy(dom + 1, "TARGET.INTERNAL", 15);
        snprintf(socks_host, sizeof socks_host, "target.internal");
        socks_port = 443;
        if (!socks_destination_allowed(0x03, dom, 443)) {
            bad("a domain differing only in case was refused; DNS names are "
                "case-insensitive and a proxy that says otherwise is broken "
                "in a way that looks like a network fault");
        } else {
            ok("a domain differing only in case is the same destination");
        }
    }

    /* ---- 2. THE REFUSALS, which are the security. */
    {
        struct in_addr a;
        inet_pton(AF_INET, "10.0.0.6", &a);
        unsigned char v4[4];
        memcpy(v4, &a, 4);
        snprintf(socks_host, sizeof socks_host, "10.0.0.5");
        socks_port = 8080;
        if (socks_destination_allowed(0x01, v4, 8080)) {
            bad("a DIFFERENT address on the right port was ALLOWED. This is "
                "the open-proxy case: a client that reached this listener can "
                "reach anything the node can reach.");
        } else {
            ok("a different address on the same port is refused");
        }
        if (socks_destination_allowed(0x01, v4, 9090)) {
            bad("the right address on a DIFFERENT port was ALLOWED, which is "
                "the same open proxy with a different target");
        } else {
            ok("the right address on a different port is refused");
        }
    }
    {
        unsigned char dom[1 + 15];
        dom[0] = 15;
        memcpy(dom + 1, "elsewhere.test", 15);
        snprintf(socks_host, sizeof socks_host, "target.internal");
        socks_port = 443;
        if (socks_destination_allowed(0x03, dom, 443)) {
            bad("a different DOMAIN was allowed, which is the open-proxy case "
                "for a named destination");
        } else {
            ok("a different domain is refused");
        }
    }
    {
        /* ⛔ A PREFIX IS NOT A MATCH. `target.internal.evil.test` and
         * `target-internal` both "start with" the named host in a way a
         * careless comparison would accept. An operator who named one host must
         * not thereby have named its neighbours. */
        unsigned char dom[1 + 26];
        dom[0] = 26;
        memcpy(dom + 1, "target.internal.evil.test", 26);
        snprintf(socks_host, sizeof socks_host, "target.internal");
        socks_port = 443;
        if (socks_destination_allowed(0x03, dom, 443)) {
            bad("a domain that merely BEGINS with the named one was allowed. "
                "A prefix is not a match, and accepting one lets a client reach "
                "a host the operator never named.");
        } else {
            ok("a domain that merely begins with the named one is refused");
        }
    }
    {
        /* ⛔ AN EMPTY OR ZERO PORT IS NOT "ANY PORT". `socks_port` is zero
         * before the operator configures anything, and a comparison that
         * ignored the port would allow a request whose port is 0 -- which is
         * not a destination, and a check that passes it is a check that is not
         * looking. */
        snprintf(socks_host, sizeof socks_host, "10.0.0.5");
        socks_port = 0;
        struct in_addr a;
        inet_pton(AF_INET, "10.0.0.5", &a);
        unsigned char v4[4];
        memcpy(v4, &a, 4);
        if (socks_destination_allowed(0x01, v4, 0)) {
            bad("with no port configured, a request for port 0 was ALLOWED. "
                "Unconfigured must mean 'nothing is allowed', not 'anything "
                "goes'.");
        } else {
            ok("with no port configured nothing is allowed, not anything");
        }
        socks_port = 8080;
    }
    {
        /* ⛔ IPV6 IS REFUSED RATHER THAN COMPARED. A relay that accepted an
         * IPv6 destination would have a second door, and there is no reason
         * for it to exist before somebody asks for one by name. A policy that
         * "cannot compare this, so allow it" is the shape this is guarding
         * against. */
        snprintf(socks_host, sizeof socks_host, "10.0.0.5");
        socks_port = 8080;
        unsigned char v6[16];
        memset(v6, 0, sizeof v6);
        v6[0] = 0x20; v6[1] = 0x01; v6[15] = 1;
        if (socks_destination_allowed(0x04, v6, 8080)) {
            bad("an IPv6 destination was ALLOWED. It cannot be the one the "
                "operator named, because the operator's name is compared as "
                "text or as IPv4; allowing it would be a second door.");
        } else {
            ok("an IPv6 destination is refused, not guessed at");
        }
    }
    {
        /* ⛔ AND A DOMAIN NAME THAT IS NOT AN ADDRESS IS STILL COMPARED AS
         * TEXT, so an operator who names `localhost` gets `localhost` and not
         * the first address that happens to resolve to it. A relay that
         * resolved the name itself would be a resolver in a cage that has none,
         * and a second place for the destination to be decided. */
        unsigned char dom[1 + 9];
        dom[0] = 9;
        memcpy(dom + 1, "localhost", 9);
        snprintf(socks_host, sizeof socks_host, "localhost");
        socks_port = 80;
        if (!socks_destination_allowed(0x03, dom, 80)) {
            bad("an operator who named `localhost` cannot reach `localhost`");
        } else {
            ok("a name is compared as text, never resolved by the relay");
        }
    }

    printf("== %d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
