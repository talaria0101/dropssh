/* main.c - the dropssh command line.
 *
 * ONE SETTINGS BLOCK, ONE PARSER, ONE PLACE THAT READS THE ENVIRONMENT. The
 * proxy and the verification policy are process-wide on purpose (util.h), so
 * there is no way for one session to verify certificates and another not
 * without it showing on the command line.
 */
#include "dropssh.h"
#include "transport.h"
#include "tls.h"
#include "util.h"
#include "ws.h"
#include "events.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *f) {
    fprintf(f,
"dropssh - dropbear, with a relay built in\n"
"\n"
"USAGE\n"
"  dropssh serve   --name N [options]      node side, inside the cage\n"
"  dropssh connect [options]               operator side; ssh ProxyCommand target\n"
"  dropssh relay   [--listen ADDR] [--name N]\n"
"  dropssh keygen  -t TYPE -f FILE\n"
"  dropssh doctor  [options]               what this machine can do, measured\n"
"  dropssh pair    [options]               node + connect tokens, ready to paste\n"
"  dropssh config  [options]               every setting and where it came from\n"
"  dropssh version\n"
"\n"
"WHAT EACH VERB IS FOR\n"
"  serve     keeps an outbound websocket to a relay and hands each paired\n"
"            session to `dropbear -i` on a socketpair. No inbound port, no\n"
"            chroot, no privsep user, no /var.\n"
"  connect   carries ssh bytes between a relay and stdin/stdout. It is what\n"
"            ssh's ProxyCommand runs, and it is the verb that gets you in.\n"
"  relay     a rendezvous relay, for a deployment that does not want to use\n"
"            someone else's.\n"
"  keygen    a host key in dropbear's format.\n"
"  doctor    the environment questions, answered by reading rather than by\n"
"            guessing: uid, passwd database, CA bundle, whether the server\n"
"            command starts here, and relay reachability by which route.\n"
"            Exits non-zero if a check failed.\n"
"  pair      a node token and a connect token, ready to paste, so a token\n"
"            never lands in shell history.\n"
"  config    every setting and where it came from: flag, environment, or\n"
"            built-in. Answers 'it ignored my flag'.\n"
"\n"
"COMMON OPTIONS\n"
"  --relay HOST        the relay host (default %s)\n"
"  --port N            relay port (default 443)\n"
"  --path P            relay request target, e.g. /connect/railway\n"
"  --name N            a reverse node name, or an operator's target name\n"
"  --token T           a relay token; sent as X-Relay-Token, never in a URL\n"
"  --mint              mint a forward token from the relay first (connect)\n"
"  --proxy HOST:PORT   an HTTP CONNECT proxy, for a cage with no egress\n"
"  --doh URL           a DoH endpoint, for a cage with no resolver\n"
"  --insecure          skip TLS verification. Off by default, on purpose.\n"
"  --server CMD        the ssh server command for `serve`\n"
"  --passwd FILE       SANDHOME_PASSWD for the server, for a cage with no\n"
"                      /etc/passwd. Without it dropbear logs\n"
"                      'Login attempt for nonexistent user' for root.\n"
"  --preload PATH      LD_PRELOAD for the server, e.g. the passwd shim.\n"
"                      A STATIC server cannot be preloaded at all.\n"
"  --once              serve one session and exit\n"
"  --json              machine-readable events, on stderr. stdout stays a\n"
"                      clean byte pipe because it is ssh's.\n"
"  -v, --verbose       say what is happening, on stderr\n"
"\n"
"TESTING OPTIONS (not for operators)\n"
"  --bound-ms N        how long `connect` waits for the node's `ready`\n"
"                      before giving up. Default is %d ms. Pass 0 for no\n"
"                      bound at all. tests/mux-probe.py reads this line out\n"
"                      of --help and uses it to prove the bound fires when\n"
"                      it is removed.\n"
"\n"
"EXAMPLES\n"
"  # an operator getting a shell, through the ajam relay, to a named node\n"
"  ssh -o ProxyCommand='dropssh connect --name mynode' root@mycage\n"
"\n"
"  # a cage registering and waiting, outbound only\n"
"  dropssh serve --name mycage --server 'dropbear -i -E -F'\n"
"\n"
"  # a one-shot to a public ssh gateway over the relay\n"
"  ssh -o ProxyCommand='dropssh connect --mint' root@railway.new\n"
"\n"
"  # before anything else, on a machine you do not know\n"
"  dropssh doctor\n"
"\n"
"  # tokens without putting one in shell history\n"
"  dropssh pair --relay relay.example:443 --name mybox\n"
"\n"
"  # why did it not use my flag\n"
"  dropssh config --relay relay.example:443 --insecure\n",
        DROPSSH_DEFAULT_RELAY, DROPSSH_READY_BOUND_MS);
}

int dropssh_version_cmd(void) {
    printf("dropssh %s (%s)\n", dropssh_version(), dropssh_gitdescribe());
    printf("tls backend: %s\n", dropssh_tls_backend());
    const char *p = dropssh_proxy_host();
    printf("egress proxy: %s\n", p ? p : "none (direct)");
    printf("tls verification: %s\n", dropssh_insecure() ? "DISABLED by --insecure" : "on");
    return 0;
}

int dropssh_keygen(const char *type, const char *file, int bits) {
    if (file == NULL) {
        fprintf(stderr, "dropssh keygen: -f FILE is required\n");
        return 2;
    }
    char cmd[1024];
    if (bits > 0) {
        snprintf(cmd, sizeof cmd, "dropbearkey -t %s -b %d -f %s", type, bits, file);
    } else {
        snprintf(cmd, sizeof cmd, "dropbearkey -t %s -f %s", type, file);
    }
    fflush(stdout);
    if (system(cmd) != 0) {
        fprintf(stderr, "dropssh keygen: dropbearkey failed. It is built from\n"
                        "the same source as the server and lives beside this\n"
                        "binary, or on PATH.\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    const char *verb = argv[1];
    if (strcmp(verb, "-h") == 0 || strcmp(verb, "--help") == 0 ||
        strcmp(verb, "help") == 0) {
        usage(stdout);
        return 0;
    }
    if (strcmp(verb, "version") == 0 || strcmp(verb, "--version") == 0) {
        return dropssh_version_cmd();
    }

    /* ⛔ THE RELAY VERB GETS THE RAW ARGV. Its options (--listen, --name) are
     * its own, and the shared parser below would refuse them as unknown, so
     * `dropssh relay --listen unix:///x.sock` printed usage and exited 2. The
     * verbs have genuinely different options and pretending otherwise costs a
     * flag that is documented in the relay's own help. */
    if (strcmp(verb, "relay") == 0) {
        return dropssh_relay_main(argc, argv);
    }

    /* ⛔ doctor, pair and config ARE ROUTED AFTER THE PARSER AND BEFORE THE
     * VERB DISPATCH, because they take the same options as the verbs that
     * talk to a relay and an operator needs `dropssh config --relay X` to
     * report the resolved relay rather than the default. The parser below
     * fills the same struct the transport verbs use, so there is one option
     * table and no way for `config` to describe a setting `serve` ignores. */

    dropssh_opts o;
    memset(&o, 0, sizeof o);
    o.relay = getenv("DROPSSH_RELAY");
    if (o.relay == NULL) {
        o.relay = DROPSSH_DEFAULT_RELAY;
    }
    o.port = 443;
    o.connect_ms = 15000;
    o.bound_ms = DROPSSH_READY_BOUND_MS;
    o.token = getenv("DROPSSH_TOKEN");
    if (o.token == NULL) {
        o.token = getenv("DROPSSH_RELAY_TOKEN");
    }
    const char *doh = getenv("DROPSSH_DOH");
    o.doh = (doh && *doh) ? doh : NULL;
    const char *ins = getenv("DROPSSH_INSECURE");
    if (ins && (*ins == '1' || *ins == 'y')) {
        o.insecure = 1;
    }

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : (usage(stderr), exit(2), ""))
        if (strcmp(a, "--relay") == 0) {
            o.relay = NEXT();
        } else if (strcmp(a, "--port") == 0) {
            o.port = atoi(NEXT());
        } else if (strcmp(a, "--path") == 0) {
            o.path = NEXT();
        } else if (strcmp(a, "--name") == 0) {
            o.name = NEXT();
        } else if (strcmp(a, "--token") == 0) {
            o.token = NEXT();
        } else if (strcmp(a, "--mint") == 0) {
            o.generate = 1;
        } else if (strcmp(a, "--doh") == 0) {
            o.doh = NEXT();
        } else if (strcmp(a, "--insecure") == 0) {
            o.insecure = 1;
        } else if (strcmp(a, "--server") == 0) {
            o.server = NEXT();
        } else if (strcmp(a, "--passwd") == 0) {
            o.passwd = NEXT();
        } else if (strcmp(a, "--preload") == 0) {
            o.preload = NEXT();
        } else if (strcmp(a, "--once") == 0) {
            o.once = 1;
        } else if (strcmp(a, "--json") == 0) {
            o.json = 1;
        } else if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
            o.verbose++;
        } else if (strcmp(a, "--connect-timeout") == 0) {
            o.connect_ms = atoi(NEXT());
        } else if (strcmp(a, "--bound-ms") == 0) {
            const char *v = NEXT();
            if (v == NULL) {
                fprintf(stderr, "dropssh: --bound-ms needs a value\n");
                return 2;
            }
            /* ⛔ PARSED WITH strtol AND CHECKED, NOT WITH atoi. `atoi("abc")`
             * is 0, and 0 IS A MEANINGFUL VALUE HERE -- it means "no bound" --
             * so a typo in this flag SILENTLY REMOVES THE GUARD it was meant to
             * set. That is the same disease as the `usage()` vararg bug where
             * an unpassed argument printed as 0: a zero that reads like a
             * number. Verified: `--bound-ms abc` was accepted with no complaint
             * before this was added.
             *
             * The end pointer is checked rather than assumed, so `60000x` is
             * rejected for the same reason `abc` is, and the range is bounded
             * because this value is compared against an unsigned clock. */
            char *end = NULL;
            errno = 0;
            long ms = strtol(v, &end, 10);
            if (end == v || (end && *end != '\0') || errno == ERANGE ||
                ms < 0 || ms > 3600000L) {
                fprintf(stderr,
                        "dropssh: --bound-ms is a time in ms between 0 and "
                        "3600000, not `%s`. 0 means no bound at all\n", v);
                return 2;
            }
            o.bound_ms = (int)ms;
        } else if (strcmp(a, "--proxy") == 0) {
            const char *p = NEXT();
            /* an explicit --proxy sets the process-wide egress, so every
             * verb in this process uses it, which is what one operator means */
            setenv("DROPSSH_PROXY", p, 1);
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "dropssh: unknown option %s\n", a);
            usage(stderr);
            return 2;
        }
        #undef NEXT
    }
    dropssh_set_insecure(o.insecure);
    /* ⛔ --json IS HONOURED OR REFUSED, NEVER ACCEPTED AND IGNORED. It was
     * accepted, set a field, and nothing read it, which is worse than refusing
     * it: an operator who passed it believed they had machine-readable output
     * and did not. Now it selects a real event stream on stderr. */
    dropssh_events_set_json(o.json);

    if (strcmp(verb, "doctor") == 0) {
        dropssh_events_banner("doctor");
        return dropssh_doctor(&o);
    }
    if (strcmp(verb, "pair") == 0) {
        dropssh_events_banner("pair");
        return dropssh_pair(&o);
    }
    if (strcmp(verb, "config") == 0) {
        dropssh_events_banner("config");
        return dropssh_config(&o);
    }
    if (strcmp(verb, "connect") == 0) {
        dropssh_events_banner("connect");
        return dropssh_connect(&o);
    }
    if (strcmp(verb, "serve") == 0) {
        dropssh_events_banner("serve");
        return dropssh_serve(&o);
    }
    if (strcmp(verb, "keygen") == 0) {
        const char *type = "ed25519";
        const char *file = NULL;
        int bits = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
                type = argv[++i];
            } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
                file = argv[++i];
            } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
                bits = atoi(argv[++i]);
            }
        }
        return dropssh_keygen(type, file, bits);
    }
    fprintf(stderr, "dropssh: unknown verb %s\n", verb);
    usage(stderr);
    return 2;
}
