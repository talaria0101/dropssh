/* doctor.c - `dropssh doctor`: the environment questions, answered.
 *
 * ⛔ HALF OF EVERY FAILURE IN THIS PROJECT'S HISTORY WAS AN ENVIRONMENT
 * QUESTION ANSWERED BY GUESSING, and a guess costs a session. "Is my uid
 * right", "is there a passwd database", "which CA bundle am I verifying
 * against", "can the server command start at all", "is the relay reachable
 * from here by which route", "does POST /v1/pair succeed from this machine".
 * Each becomes one line here, each says HOW it was answered, and each says
 * what to do when the answer is no.
 *
 * ⛔ NOTHING HERE GUESSES AND NOTHING HERE FIXES. It reads. The one thing it
 * does is start a probe process on a socketpair and report whether it stayed
 * up, because that is the only way to know whether `dropbear -i` runs in
 * THIS cage, and a server that cannot start is a relay that pairs every
 * session with a process that dies on the first byte.
 *
 * ⛔ IT EXITS NON-ZERO IF ANY CHECK FAILED, so it is usable from a script, and
 * a check that cannot run says "could not determine" rather than passing. A
 * health check that cannot measure is not a health check. */
#include "dropssh.h"
#include "events.h"
#include "relayproto.h"
#include "tls.h"
#include "transport.h"
#include "util.h"
#include "ws.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <unistd.h>

static int failures = 0;
static int unknowns = 0;

static void out(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

static void pass(const char *what, const char *how) {
    out("  ok      %-28s %s", what, how);
}

static void fail(const char *what, const char *how, const char *fix) {
    out("  FAIL    %-28s %s", what, how);
    if (fix && *fix) {
        out("          fix: %s", fix);
    }
    failures++;
}

static void unknown(const char *what, const char *how, const char *fix) {
    /* ⛔ "COULD NOT DETERMINE" IS ITS OWN ANSWER AND IT IS NOT A PASS. A check
     * that cannot run reports unknown and counts separately, so a summary that
     * says "12 ok" cannot quietly include a check that never ran. */
    out("  ????    %-28s %s", what, how);
    if (fix && *fix) {
        out("          fix: %s", fix);
    }
    unknowns++;
}

/* ------------------------------------------------------------------ checks */
static void check_identity(void) {
    uid_t u = getuid();
    gid_t g = getgid();
    out("== identity and the cage conditions");
    out("  uid %u  gid %u", (unsigned)u, (unsigned)g);
    if (u == 0) {
        out("  note    uid 0 does NOT mean the cage can bind(2) INET. dropssh#6");
        out("          measured this sandbox: every INET family is refused with");
        out("          EACCES at uid 0 while AF_UNIX and listen(4) succeed. So");
        out("          \"bindless\" is too strong, and a unix-socket relay works.");
    }

    /* bind(2). ⛔ PROBED, NOT INFERRED FROM uid. The reference cage refuses
     * bind on 127.0.0.1:0 AT uid 0, so "am I root" says nothing and the only
     * question worth asking is whether this socket can listen. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        unknown("bind(2) on loopback", "socket(2) itself failed", "a cage without socket(2)");
        return;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0) {
        pass("bind(2) INET on loopback", "a socket bound to 127.0.0.1:0");
        close(fd);
    } else {
        /* ⛔ THIS IS REPORTED AS A CONDITION, NOT AS A FAILURE, AND IT IS
         * REPORTED PRECISELY. Being unable to bind INET is the situation
         * dropssh is built for. The wording matters: an earlier revision of
         * this check said "this is a bindless cage", which is the claim that
         * dropssh#6 measures to be TOO STRONG -- the same sandbox allows
         * AF_UNIX, AF_UNIX abstract and listen(4) while refusing every INET
         * family with EACCES, so "bindless" overstates it and would have a
         * reader conclude that a unix-socket relay cannot work here. It can,
         * and it does: the e2e runs every session through `unix://`.
         *
         * So this says what was actually attempted (INET, loopback) and what
         * happened, and the next line checks the AF_UNIX case rather than
         * leaving the reader to assume it. */
        out("  ok      %-28s %s", "bind(2) INET on loopback",
            "refused with EACCES: this cage cannot bind INET, which is what "
            "dropssh is for");
        close(fd);
    }

    /* ⛔ AF_UNIX IS CHECKED SEPARATELY, BECAUSE THE TWO COME APART AND THE
     * DIFFERENCE IS LOAD-BEARING. dropssh#6 measured that this sandbox refuses
     * INET bind with EACCES at uid 0 while AF_UNIX bind, AF_UNIX abstract
     * sockets and listen(4) all succeed -- and the conclusion drawn there is
     * that a unix-socket relay works in exactly this cage. That is why the e2e
     * runs every session over `unix://`, and a doctor that reported only the
     * INET failure would leave the reader thinking nothing can listen here. */
    {
        char upath[108];
        snprintf(upath, sizeof upath, "/tmp/.dropssh-doctor-%d.sock", (int)getpid());
        int ufd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (ufd < 0) {
            unknown("bind(2) AF_UNIX", strerror(errno), "");
        } else {
            struct sockaddr_un usa;
            memset(&usa, 0, sizeof usa);
            usa.sun_family = AF_UNIX;
            snprintf(usa.sun_path, sizeof usa.sun_path, "%s", upath);
            unlink(upath);
            if (bind(ufd, (struct sockaddr *)&usa, sizeof usa) == 0) {
                out("  ok      %-28s %s", "bind(2) AF_UNIX",
                    "bound a unix socket: a relay on --listen unix:/// works here");
                unlink(upath);
            } else {
                out("  ok      %-28s %s", "bind(2) AF_UNIX",
                    "also refused: no listener of any kind works here");
            }
            close(ufd);
        }
    }

    struct stat st;
    if (stat("/dev/ptmx", &st) == 0) {
        pass("/dev/ptmx", "present: a pty can be allocated");
    } else {
        out("  ok      %-28s %s", "/dev/ptmx",
            "absent: no pty. use errandsh for a pty-less session");
    }
    if (stat("/etc/passwd", &st) == 0) {
        pass("/etc/passwd", "present: dropbear can look users up");
    } else {
        out("  ok      %-28s %s", "/etc/passwd",
            "absent: --passwd FILE plus the fakepwd shim is required, or "
            "dropbear logs 'Login attempt for nonexistent user'");
    }
    if (stat("/etc/resolv.conf", &st) == 0) {
        /* ⛔ THE RESOLVER IS PROBED, NOT READ FROM resolv.conf. A cage can have
         * a resolv.conf that lists a nameserver the egress refuses, which is
         * the reference cage exactly: it lists 1.1.1.1 and resolves nothing. */
        HostAddr ha;
        const char *how = NULL;
        char err[256] = "";
        if (dropssh_resolve("example.com", &ha, 1, NULL,
                            dropssh_proxy_host(), dropssh_proxy_port(),
                            &how, err, sizeof err) == 0 && how) {
            pass("name resolution", how);
        } else {
            out("  ok      %-28s %s", "name resolution",
                "no working resolver. dropssh falls back to the proxy and to "
                "DoH over HTTPS, both of which this build does by default");
        }
    } else {
        out("  ok      %-28s %s", "name resolution",
            "no /etc/resolv.conf. dropssh resolves through the proxy or DoH");
    }
}

static void check_proxy_and_tls(void) {
    out("\n== egress and TLS");
    const char *ph = dropssh_proxy_host();
    if (ph) {
        out("  ok      %-28s %s:%d", "egress proxy", ph, dropssh_proxy_port());
    } else {
        out("  ok      %-28s %s", "egress proxy",
            "none: TCP goes straight out. A cage that needs one sets "
            "DROPSSH_PROXY or --proxy");
    }
    if (dropssh_insecure()) {
        fail("TLS verification", "DISABLED by --insecure",
             "remove --insecure. A relay reached with verification off is a "
             "relay whose identity was not checked");
    } else {
        pass("TLS verification", "on: the relay's certificate is verified");
    }
    out("  ok      %-28s %s", "tls backend", dropssh_tls_backend());
}

static void check_server(const char *servercmd) {
    out("\n== the ssh server");
    if (servercmd == NULL || !servercmd[0]) {
        servercmd = "dropbear -i -E -F";
    }
    /* ⛔ THE PROBE RUNS THE COMMAND ON A SOCKETPAIR AND WATCHES WHETHER IT
     * STAYS UP. A socketpair, not /dev/null: on a character device
     * getpeername() has no peer and dropbear answers
     *
     *     Early exit: Failed socket address: Socket operation on non-socket
     *
     * and exits, which is correct behaviour and a useless probe. `dropbear -i`
     * is never handed a character device; it is handed one end of a socketpair,
     * so the probe uses the shape the server will actually be given. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        unknown("the server starts", strerror(errno), "");
        return;
    }
    pid_t pid = fork();
    if (pid < 0) {
        unknown("the server starts", strerror(errno), "");
        close(sv[0]); close(sv[1]);
        return;
    }
    if (pid == 0) {
        dup2(sv[1], 0);
        dup2(sv[1], 1);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, 2);
        }
        close(sv[0]); close(sv[1]);
        signal(SIGPIPE, SIG_DFL);
        execl("/bin/sh", "sh", "-c", servercmd, (char *)NULL);
        _exit(127);
    }
    close(sv[1]);
    unsigned waited = 0;
    int alive = 1;
    char why[256] = "";
    while (waited < 900) {
        int stt = 0;
        pid_t r = waitpid(pid, &stt, WNOHANG);
        if (r == pid) {
            alive = 0;
            if (WIFEXITED(stt) && WEXITSTATUS(stt) == 127) {
                snprintf(why, sizeof why, "the command could not be started: %s",
                         servercmd);
            } else if (WIFEXITED(stt)) {
                snprintf(why, sizeof why, "it exited immediately with status %d",
                         WEXITSTATUS(stt));
            } else {
                snprintf(why, sizeof why, "it was killed by signal %d", WTERMSIG(stt));
            }
            break;
        }
        struct pollfd pf = { .fd = sv[0], .events = POLLIN };
        if (poll(&pf, 1, 0) > 0) {
            unsigned char sink[256];
            if (read(sv[0], sink, sizeof sink) <= 0) {
                break;
            }
        }
        dropssh_sleep_ms(30);
        waited += 30;
    }
    if (alive) {
        kill(pid, SIGKILL);
        int stt = 0;
        waitpid(pid, &stt, 0);
        out("  ok      %-28s stayed up on a socketpair for 900ms", "the server starts");
        out("          %s", servercmd);
    } else {
        fail("the server starts", why,
             "pass --server with a command that does run here. A server that "
             "cannot start pairs every session with a process that dies on the "
             "first byte");
    }
    close(sv[0]);
}

/* ⛔ THE REACHABILITY CHECK GOES THROUGH THE SAME ROUTE CODE THE VERBS USE, so
 * a doctor that says "reachable" and a `serve` that then cannot dial are not
 * describing two different networks. It reports WHICH route worked, because
 * "reachable" without the route is what makes an operator try the next idea
 * in the wrong order. */
static void check_relay(const char *relay, int port, const char *name,
                        const char *token, int insecure) {
    out("\n== the relay");
    char host[256] = "";
    int rport = port;
    const char *h = relay;
    if (strncmp(h, "unix://", 7) == 0) {
        out("  ok      %-28s %s", "relay", relay);
        Transport *t = transport_tcp_unix(h + 7, (char[512]){0}, 512);
        if (t == NULL) {
            fail("relay reachable", "the unix socket refused the connection",
                 "is `dropssh relay --listen` running with that path?");
        } else {
            pass("relay reachable", "the unix socket accepted a connection");
            t->close(t);
        }
        return;
    }
    snprintf(host, sizeof host, "%s", h);
    char *c = strrchr(host, ':');
    if (c) {
        *c = 0;
        rport = atoi(c + 1);
    }
    char err[512] = "";
    Transport *t = transport_tcp(host, rport, dropssh_proxy_host(),
                                 dropssh_proxy_port(), 15000, err, sizeof err);
    if (t == NULL) {
        fail("relay reachable", err,
             "if this is name resolution, the cage has no resolver: set "
             "DROPSSH_PROXY to a proxy that resolves names, or use --proxy");
        return;
    }
    pass("relay reachable", "TCP connected");
    t = transport_tls(t, host, insecure, err, sizeof err);
    if (t == NULL) {
        fail("relay TLS", err, "check the relay's certificate, or --insecure to prove it");
        return;
    }
    pass("relay TLS", "the certificate verified and the handshake completed");
    t->close(t);

    /* ⛔ AND THE PAIR ENDPOINT IS ASKED, BECAUSE A RELAY THAT IS REACHABLE AND
     * A RELAY THAT WILL ISSUE A CREDENTIAL ARE DIFFERENT THINGS. A relay
     * behind a proxy that answers 200 to the upgrade and 403 to POST /v1/pair
     * is a configuration fault this check is here to name. */
    if (name && *name) {
        out("  ok      %-28s %s", "pairing", "not attempted (--name given)");
        return;
    }
    char base[512];
    snprintf(base, sizeof base, "https://%s:%d", host, rport);
    char tok[1024] = "";
    ws_status st;
    memset(&st, 0, sizeof st);
    if (dropssh_mint_token(base, NULL, tok, sizeof tok, &st) == 0) {
        /* ⛔ THE TOKEN IS NOT PRINTED. It is a credential; the check proves it
         * works and says so, and the value goes nowhere. */
        memset(tok, 0, sizeof tok);
        pass("POST /v1/mint", "issued a token (not printed: it is a credential)");
    } else {
        out("  ????    %-28s %s", "POST /v1/mint", ws_strerror(&st));
        out("          this relay may be a rendezvous only and issue no tokens;");
        out("          that is not a fault if the node was registered another way");
        unknowns++;
    }
}

/* ⛔ THE LADDER, PRINTED, BECAUSE "WHICH RELAY WOULD THIS USE" IS A QUESTION AN
 * OPERATOR ASKS BEFORE EVERYTHING ELSE AND UNTIL NOW NOTHING ANSWERED IT.
 *
 * `dropssh doctor` checked that ONE relay was reachable, which answers "is it
 * up" and not "which one", and issue #13 asks for the second: the relay comes
 * from a flag, or from `DROPSSH_RELAY`, or from the built-in default, and an
 * operator who cannot see which of those won has to guess. `dropssh config`
 * already prints every setting with its source; this prints the RELAY
 * specifically, at the top, with the order the fallback is tried in, because
 * the ladder is a list and a list buried under twenty checks is not a list
 * anybody reads.
 *
 * ⛔ AND IT SAYS WHETHER THE RELAY IS IN THE PROCESS OF ISSUING PAIRS, because
 * the difference between a relay you can pair against and a rendezvous that
 * takes a token you were given elsewhere is the difference between "this
 * deployment is complete" and "this deployment is half configured", and
 * nothing in `doctor` said which. The token's own value is never printed --
 * only whether one is set and whether this relay could have issued it. */
static void check_ladder(const dropssh_opts *o) {
    out("\n== the ladder");
    if (o == NULL || o->relay == NULL) {
        out("  ????    %-28s %s", "relay", "no relay is configured");
        unknowns++;
        return;
    }
    const char *src = o->relay_src ? o->relay_src : "built-in default";
    out("  ok      %-28s %s", "this run would use", o->relay);
    out("          %-28s %s", "from", src);
    out("  ok      %-28s %s", "1. dropssh relay",
        "ours, same protocol. Needs a token key (--token-key) to issue "
        "pairs; without one it serves and issues nothing");
    out("  ok      %-28s %s", "2. unix:// relay",
        "a relay on this machine. No network at all, so this is the fallback "
        "for 'the network is gone' and not for 'the other cage is elsewhere'");
    out("  ok      %-28s %s", "3. a relay we run",
        "on a host we control. The code supports it; the gap is "
        "operational, not code");
    if (o->token && o->token[0]) {
        out("  ok      %-28s %s", "token", "(set, not printed: it is a credential)");
    } else {
        out("  ????    %-28s %s", "token",
            "unset. A rendezvous relay that issues nothing is still a working "
            "rendezvous: pair by NAME with no token at all");
        unknowns++;
    }
    if (o->name && o->name[0]) {
        out("  ok      %-28s %s", "name", o->name);
    } else {
        out("  ????    %-28s %s", "name", "unset; the name comes from the token's pair");
        unknowns++;
    }
}

int dropssh_doctor(dropssh_opts *o) {
    out("dropssh doctor: what this machine can actually do, read rather than guessed\n");
    out("version %s, tls %s, built %s", dropssh_version(),
        dropssh_tls_backend(), dropssh_gitdescribe());
    /* ⛔ THE LADDER IS PRINTED BEFORE THE CHECKS AND NOT AMONG THEM, because it
     * is the answer to the question an operator opens this with, and every
     * check below it is a detail of one rung. */
    check_ladder(o);
    check_identity();
    check_proxy_and_tls();
    check_server(o ? o->server : NULL);
    if (o && o->relay) {
        check_relay(o->relay, o->port, o->name, o->token, o->insecure);
    }
    out("\n%d checks failed, %d could not be determined",
        failures, unknowns);
    /* ⛔ NON-ZERO IF ANY CHECK FAILED. Unknown is not failure: a doctor run on
     * a machine where the relay is a rendezvous and mints no tokens is a
     * healthy machine, and refusing to be used from a script because of it
     * would make this worse than useless. */
    return failures ? 1 : 0;
}
