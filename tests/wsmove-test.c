/* wsmove-test.c - the ONE OWNER PER SESSION contract, asserted on the artefact.
 *
 * ⛔ WHY THIS IS A SEPARATE BINARY AND NOT A LINE IN THE PROBE.
 *
 * U2 was 0/6 for a reason that was itself the finding: the operator's
 * WsSession is MOVED into the Client rather than copied, and every refusal
 * path that ran before the move was ABOVE it, so no existing case could see
 * the difference between a move and a copy. Closing U2 with a timing case
 * would repeat the mistake -- a case that passes for the wrong reason is
 * worse than no case, and this project has shipped four of those.
 *
 * The property U2 is about is not a race. It is an OWNERSHIP property: after
 * `ws_move`, the source session owns nothing, so closing it is a no-op rather
 * than a second free, and no number of racing threads can change that. So it is
 * asserted directly, on the real compiled `ws.c`, by the only means that can
 * distinguish a move from a copy: closing the source afterwards and observing
 * that it did not free what the destination owns.
 *
 * ⛔ AND IT IS A PLANT-TEST IN ITS OWN RIGHT. The first version of this file
 * asserted only that the source was "empty", which a copy with a memset also
 * satisfies -- that is, the test would have passed against the very defect it
 * exists to catch. So the assertion here is stronger and behavioural: after the
 * move, the destination's session must still be fully usable (it can still
 * write and still reports itself open), and the source must be inert. A copy
 * without a clear fails the first half; a clear without a move fails the
 * second. Only `ws_move` passes both.
 *
 * ⛔ IT LINKS THE REAL `ws.c` AND THE REAL `util.c`. The one stub is `tls_post`,
 * which is on the token-mint HTTP path and is not touched here. Everything the
 * test asserts about is the shipping code, not a copy of it, which is the
 * difference between this and a test that re-implements the contract and
 * passes when the product does not.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/ws.h"
#include "../src/transport.h"

/* ---- the one stub the test needs ------------------------------------------
 *
 * `ws.c` calls `tls_post` for the token-mint and pair HTTP paths, which pull in
 * mbedTLS. That path is not exercised here, and the stub returns -1 so that
 * any accidental reach for the real network is a failure rather than a silent
 * success. Everything else `ws.c` references (`dropssh_random`,
 * `dropssh_ws_accept`, the proxy accessors) is linked from the real
 * `util.c`, so the code under test is the shipping code and not a copy of it.
 */
int tls_post(const char *b, const char *p, const char *b2, const char *h,
             const char *d, size_t dl, char *o, size_t ol, int *s) {
    (void)b; (void)p; (void)b2; (void)h; (void)d; (void)dl; (void)o; (void)ol; (void)s;
    return -1;
}

static int pass = 0, fail = 0;
static void ok(const char *what)  { printf("  ok    %s\n", what); pass++; }
/* ⛔ VARIADIC, BECAUSE EVERY NEGATIVE CASE NAMES WHAT IT WAS REFUSED FOR. A
 * fixed-argument `bad()` forces each into a formatted buffer, and a `bad()` call
 * with a `%s` in it and no argument prints a literal `%s` and looks like a pass.
 * Making the formatter the only way in removes that. */
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

/* A transport that records writes and never blocks, so a write to a live
 * session is observable and a write to an inert one is not. */
typedef struct {
    Transport t;
    unsigned  writes;
} FakeT;

static int fake_write(Transport *t, const void *b, size_t n) {
    (void)b;
    FakeT *f = (FakeT *)t;
    f->writes++;
    return (n == 0) ? -1 : 0;   /* ⛔ a zero-length write is a failure, so a
                                 * closed session's write cannot look like a
                                 * successful one */
}
static void fake_close(Transport *t) { (void)t; }
static int fake_read(Transport *t, void *b, size_t n, size_t *out, int *eof) {
    (void)t; (void)b; (void)n;
    if (out) { *out = 0; }
    if (eof) { *eof = 1; }
    return -1;
}

int main(void) {
    /* ⛔ UNBUFFERED, BECAUSE A PLANT DIES BY SIGSEGV AND A BUFFERED SUMMARY IS
     * LOST WITH IT. The whole point of this file is to print WHICH rule broke
     * when the one-owner property is violated, and a copy violates it by
     * double-freeing, which takes the process out before a full buffer is
     * ever written. A test whose failure output is discarded by the crash it
     * was written to catch has caught nothing. */
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("== the one-owner-per-session contract (U2), on the real ws.c\n");

    /* ---- 1. After a move the DESTINATION still works. A copy that was
     *      cleared would leave the destination with no transport, so this is
     *      the half a broken move fails. */
    {
        WsSession dst, src;
        FakeT ft;
        memset(&ft, 0, sizeof ft);
        ft.t.write = fake_write;
        ft.t.close = fake_close;
        ft.t.read = fake_read;
        memset(&dst, 0, sizeof dst);
        memset(&src, 0, sizeof src);
        src.t = &ft.t;
        src.rbuf.p = malloc(64);          /* a buffer the session OWNS */
        src.rbuf.len = 8;
        src.rbuf.cap = 64;

        ws_move(&dst, &src);

        /* ⛔ THE SOURCE IS CHECKED FIRST, BEFORE ANY CLOSE, AND THE ORDER IS
         * THE POINT. A copy (the U2 plant) leaves the source owning the same
         * buffer as the destination, so the first `ws_close` on either of them
         * frees memory the other still points at and the test binary dies with
         * a SIGSEGV before it can print which rule was broken. A test that
         * reports its failure as a segfault has caught the defect but named
         * nothing, which is the "a failure that names the wrong thing" problem
         * this file exists to stop. So the ownership question is asked while
         * both sessions are still intact, and only then is anything freed. */
        if (src.t != NULL || src.rbuf.p != NULL) {
            bad("after ws_move the SOURCE still owns the session (transport "
                "or buffer still set). A move must leave the source owning "
                "nothing; a copy leaves two names for one allocation and the "
                "first close frees what the other still points at.");
        } else {
            ok("after ws_move the source owns nothing: a move, not a copy");
        }

        if (dst.t != &ft.t) {
            bad("after ws_move the destination does not own the transport");
        } else if (dst.rbuf.p == NULL) {
            bad("after ws_move the destination does not own the buffer");
        } else {
            /* The destination must still be writable, and the write must
             * actually reach the transport. */
            unsigned before = ft.writes;
            int rc = ws_write(&dst, (const unsigned char *)"x", 1);
            if (rc != 0) {
                bad("the destination session is not writable after a move");
            } else if (ft.writes != before + 2) {
                /* one write for the header, one for the 1-byte payload */
                bad("the destination session's write did not reach the "
                    "transport after a move");
            } else {
                ok("the destination session owns the session and still works "
                   "after a move");
            }
        }
        /* If the source was not inert, `ws_close(&dst)` would free a buffer
         * the source also owns and the process would die before the summary
         * printed. The defect is already reported; do not free into it. */
        if (src.t == NULL && src.rbuf.p == NULL) {
            ws_close(&dst);
        } else {
            free(dst.rbuf.p);
        }
    }

    /* ---- 2. After a move the SOURCE is inert, and closing it is a no-op.
     *      This is the half that a clear-without-a-move fails, and the half
     *      that makes every existing `ws_close(&ws)` on a refusal path safe. */
    {
        WsSession dst, src;
        FakeT ft;
        memset(&ft, 0, sizeof ft);
        ft.t.write = fake_write;
        ft.t.close = fake_close;
        ft.t.read = fake_read;
        memset(&dst, 0, sizeof dst);
        memset(&src, 0, sizeof src);
        src.t = &ft.t;
        src.rbuf.p = malloc(64);
        src.rbuf.len = 8;
        src.rbuf.cap = 64;

        ws_move(&dst, &src);

        if (src.t != NULL) {
            bad("the source still owns a transport after a move");
        } else if (src.rbuf.p != NULL) {
            bad("the source still owns a buffer after a move");
        } else {
            ok("the source owns nothing after a move: no transport, no buffer");
        }

        /* The decisive one: closing the source must not double free, and must
         * not shut the transport the destination is using. `free()` on a
         * pointer that is NULL is well defined, so a correct move is silent
         * here while a copy would abort in the allocator. */
        unsigned before = ft.writes;
        /* ⛔ INERTNESS IS RECORDED IMMEDIATELY AFTER THE MOVE, NOT RE-READ LATER.
         * The obvious guard -- "only free if the source looks inert" -- is
         * wrong, and it was wrong here: `ws_close` on the source ZEROES it, so
         * by the time the guard runs the source always looks inert and the
         * guard always passes. On a copy that is exactly the double free it
         * was meant to prevent. The question has to be asked while the source
         * still holds the state the move gave it, and the answer kept. */
        int moved_inert = (src.t == NULL && src.rbuf.p == NULL);
        if (!moved_inert) {
            bad("after ws_move the source still owns the session; a move must "
                "leave the source owning nothing and a copy does not");
        }
        ws_close(&src);
        ws_close(&src);            /* and a SECOND close, because every close
                                     * path in relay.c may run more than once */
        if (!moved_inert) {
            /* The source's close above has already freed a buffer `dst` also
             * points at. Report what that means and stop; freeing here would
             * be the double free this block exists to describe. */
            bad("the source was not inert, so the source's close freed a "
                "buffer the destination still owns: this is the aliasing, and "
                "it is why the two closes above are not both safe");
            return 1;
        }
        if (ft.writes != before) {
            bad("closing the moved-from source still wrote to the shared "
                "transport: the two names are not inert and not independent");
        } else {
            ok("closing the moved-from source is inert, twice over");
        }
        /* The destination must be untouched by the source's close. */
        if (dst.t == NULL) {
            bad("closing the moved-from source also closed the destination's "
                "transport");
        } else {
            ok("the destination's transport survives the source's close");
        }
        /* ⛔ THE FREE IS GATED ON THE RECORDED ANSWER, NOT ON THE SOURCE'S
         * CURRENT STATE, for the reason given above. */
        if (moved_inert) {
            ws_close(&dst);
        }
    }

    /* ---- 3. A write to a moved-from session returns an error and does not
     *      dereference a NULL transport.
     *
     * ⛔ THIS IS A REAL DEFECT THIS TEST WAS WRITTEN AGAINST, not a
     * hypothetical. `ws_close` used to NULL `ws->t` and leave `ws->closed`
     * clear, and the write paths tested only `ws->closed`; `send_frame` then
     * dereferenced a NULL `t`. A moved-from session has `t == NULL` and
     * `closed == 0`, so a late write on a moved-from session crashed the relay
     * -- and the operator's `!open_ok` refusal is exactly one such write away.
     */
    {
        WsSession dst, src;
        FakeT ft;
        memset(&ft, 0, sizeof ft);
        ft.t.write = fake_write;
        ft.t.close = fake_close;
        ft.t.read = fake_read;
        memset(&dst, 0, sizeof dst);
        memset(&src, 0, sizeof src);
        src.t = &ft.t;
        src.rbuf.p = malloc(64);
        src.rbuf.len = 8;
        src.rbuf.cap = 64;
        ws_move(&dst, &src);
        /* ⛔ THE INERTNESS CHECK COMES BEFORE THE WRITE, NOT AFTER IT. On a
         * copy the two names share a transport, so a write through `src` is a
         * write through the destination's socket, and asking the question
         * after asking the question would mean the write had already happened
         * on a session the previous block reported as aliased. The property
         * under test is that a moved-from session refuses writes, and a
         * session that is not moved-from is not the thing under test. */
        if (src.t != NULL) {
            bad("this build's ws_move is a copy, so the "
                "write-on-a-moved-from-session check does not apply");
            printf("== %d passed, %d failed\n", pass, fail);
            return 1;
        }
        int rc = ws_write(&src, (const unsigned char *)"y", 1);
        int rct = ws_write_text(&src, (const unsigned char *)"z", 1);
        if (rc != -1 || rct != -1) {
            char msg[256];
            snprintf(msg, sizeof msg,
                     "a write on a moved-from session returned %d/%d, expected "
                     "-1 for both: the write paths do not see that the session "
                     "is inert", rc, rct);
            bad(msg);
        } else {
            ok("a write on a moved-from session is refused (-1) rather than "
               "dereferencing a NULL transport");
        }
        if (src.t == NULL) {
            ws_close(&dst);
        } else {
            free(dst.rbuf.p);
        }
    }

    /* ---- 4. A SESSION WHOSE DECODER FAILED, WHICH IS A DIFFERENT STATE FROM
     * A CLOSED ONE AND IS THE ONLY ONE THAT NEEDS `ws->closed`.
     *
     * ⛔ THIS CASE EXISTS BECAUSE REVIEW 3 PLANTED THE ABSENCE OF `ws->closed`
     * AND EVERY EARLIER ASSERTION STILL PASSED. That is the finding: the guard
     * could not fail, and it is the same shape this project has shipped four
     * times.
     *
     * The two write paths test `ws->closed` AND `ws->t == NULL`, and every
     * state this file built until now had BOTH set, because every one of them
     * was produced by `ws_close`, which nulls `t`. So `closed` was untested
     * next to a well-tested pair of braces.
     *
     * The states are genuinely different and the difference is load bearing. A
     * framing error sets `ws->closed = 1` and LEAVES `t` alone, because the
     * transport is still perfectly usable and the session is over for a
     * protocol reason rather than a socket one. Remove the flag and a write
     * onto that session goes out on a socket whose reader has already declared
     * the framing invalid, which is how a half-decoded stream gets answered
     * with data the peer cannot parse.
     *
     * ⛔ AND A REVIEWER SHOULD KNOW WHAT THIS CASE DOES NOT ESTABLISH, BECAUSE
     * THE PLANT MATRIX FOUND IT OUT BY FAILING TO CATCH A PLANT.
     *
     * `ws_close` no longer setting `ws->closed` is a plant this case does NOT
     * catch, and the reason is a fact about the product rather than a weakness
     * in the test: **a WsSession is never re-armed after `ws_close`.** Nothing
     * calls `ws_client` or `ws_server_peek` on a closed session; the only
     * transitions are fresh-init and `ws_move`. So "closed, and `t` is live
     * again" cannot be constructed by any path in the product, which means the
     * state the plant would create is UNREACHABLE and there is nothing for a
     * test to observe.
     *
     * Two ways to read that, and the second is the one to hold:
     *
     *   flattering  "the flag is redundant, drop it"
     *   correct     the flag and the pointer are TWO representations of one
     *               fact, set by DIFFERENT paths, and only the combination is
     *               safe. `ws_close` nulls `t`; a framing error sets `closed`
     *               and leaves `t`, because the transport is fine and the
     *               session is over for a protocol reason. Removing `closed`
     *               makes the second path unsound for a reason no test in
     *               this repository can currently demonstrate, because
     *               demonstrating it needs a decoder stub that feeds bytes on
     *               demand and the first attempt at one took an illegal
     *               instruction out of the run.
     *
     * So the case is here because the flag is load-bearing TODAY and the
     * assertion that would prove it needs an instrument this file does not
     * have. Saying so here is the point; a comment claiming the flag is
     * covered would be the claim this repository has shipped four times. */
    {
        WsSession ws;
        FakeT ft;
        memset(&ft, 0, sizeof ft);
        ft.t.write = fake_write;
        ft.t.close = fake_close;
        ft.t.read = fake_read;
        memset(&ws, 0, sizeof ws);
        ws.t = &ft.t;                 /* ⛔ THE TRANSPORT IS STILL LIVE */
        ws.closed = 1;                /* ⛔ ONLY THE DECODER FAILED */

        int rc = ws_write(&ws, (const unsigned char *)"x", 1);
        int rct = ws_write_text(&ws, (const unsigned char *)"y", 1);
        if (rc != -1 || rct != -1) {
            bad("a write on a session whose DECODER failed was accepted "
                "(%d/%d). `closed` and `t == NULL` are two different ways of "
                "being finished and only this one sets the first without the "
                "second, so a write here goes out on a socket the reader has "
                "already declared invalid", rc, rct);
        } else {
            ok("a write on a session whose decoder failed is refused, which is "
               "the only thing `ws->closed` is for");
        }
        if (ws.t != &ft.t) {
            bad("the test itself is wrong: it must leave the transport live, "
                "or it is re-testing the moved-from case and is asserting "
                "nothing about `closed`");
        }
    }

    return fail ? 1 : 0;
}
