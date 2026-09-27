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
"  -v, --verbose       say what is happening, on stderr\n"
"\n"
"EXAMPLES\n"
"  # an operator getting a shell, through the ajam relay, to a named node\n"
"  ssh -o ProxyCommand='dropssh connect --name mynode' root@mycage\n"
"\n"
"  # a cage registering and waiting, outbound only\n"
"  dropssh serve --name mycage --server 'dropbear -i -E -F'\n"
"\n"
"  # a one-shot to a public ssh gateway over the relay\n"
"  ssh -o ProxyCommand='dropssh connect --mint' root@railway.new\n",
        DROPSSH_DEFAULT_RELAY);
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

    dropssh_opts o;
    memset(&o, 0, sizeof o);
    o.relay = getenv("DROPSSH_RELAY");
    if (o.relay == NULL) {
        o.relay = DROPSSH_DEFAULT_RELAY;
    }
    o.port = 443;
    o.connect_ms = 15000;
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

    if (strcmp(verb, "connect") == 0) {
        return dropssh_connect(&o);
    }
    if (strcmp(verb, "serve") == 0) {
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
