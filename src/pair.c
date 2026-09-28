/* pair.c - `dropssh pair` and `dropssh config`.
 *
 * ⛔ `pair` EXISTS BECAUSE THE OPERATOR USED TO RUN curl, AND A TOKEN IN SHELL
 * HISTORY IS A TOKEN IN EVERY LOG THAT EVER READS THAT HISTORY. This prints a
 * node token and a connect token ready to paste, and it does not echo them
 * anywhere else: the two lines on stdout are the only place they appear, and
 * the operator's shell history records the COMMAND, not the output.
 *
 * ⛔ AND IT PRINTS BOTH ROLES FROM ONE CALL, BECAUSE THEY COME FROM ONE PAIR.
 * An operator who runs the relay's pair endpoint by hand gets a name, a node
 * token and a connect token, and has to know which is which and which goes to
 * which side. Getting that backwards produces a node that registers and an
 * operator that is refused with 403, and the 403 says "no token, or the wrong
 * token" and not "you swapped them".
 *
 * ⛔ `config` PRINTS EVERY SETTING AND WHERE IT CAME FROM, BECAUSE A WRONG
 * SETTING DISCOVERED BY READING THE RESOLVED OUTPUT IS A CLASS OF REPORT THAT
 * OTHERWISE ARRIVES AS "it ignored my flag". Each line names its source:
 * flag, environment, or built-in. A setting whose source is not printed cannot
 * be debugged, and a flag that is accepted and overridden by the environment
 * with nothing saying so is indistinguishable from a bug in the flag. */
#include "dropssh.h"
#include "events.h"
#include "tls.h"
#include "transport.h"
#include "util.h"
#include "ws.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Which of these a value came from. The order matters: a flag beats the
 * environment, and the environment beats the built-in, and the printed line
 * says so rather than leaving the reader to guess. */
static const char *src_flag = "flag";
static const char *src_env  = "environment";
static const char *src_def  = "built-in default";

int dropssh_pair(dropssh_opts *o) {
    char base[512];
    snprintf(base, sizeof base, "https://%s", o->relay);
    RelayPair p;
    ws_status st;
    memset(&st, 0, sizeof st);
    if (dropssh_request_pair(base, &p, &st) != 0) {
        fprintf(stderr, "dropssh pair: %s could not issue a pair: %s\n",
                o->relay, ws_strerror(&st));
        fprintf(stderr, "  a rendezvous relay that issues no credentials is still a\n");
        fprintf(stderr, "  working rendezvous: pair by NAME with no token at all --\n");
        fprintf(stderr, "  in the cage `dropssh serve --name N`, here `dropssh "
                        "connect --name N`.\n");
        return 4;
    }
    /* ⛔ THE NAME, AND THE TWO DIFFERENT TOKENS, EACH ONCE, AND NOTHING ELSE.
     * The stop token is NOT printed: it is a credential that can tear down the
     * pair, and a terminal scrollback is not a place for one. The expiry is
     * printed because it is not a secret and it tells the operator when to come
     * back. */
    printf("name %s\n", p.name);
    printf("node    --name %s --token %s\n", p.name, p.node_token);
    printf("connect --name %s --token %s\n", p.name, p.connect_token);
    if (p.expires_ms > 0) {
        long long secs = p.expires_ms / 1000;
        printf("\n# this pair expires in %lld seconds (the relay said %lld ms "
               "since epoch).\n", secs, p.expires_ms);
    }
    printf("# In the cage:   dropssh serve   --name %s --token <the node line>\n",
           p.name);
    printf("# On this box:   ssh -o ProxyCommand='dropssh connect --name %s "
           "--token <the connect line>' root@%s\n", p.name, p.name);
    /* ⛔ THE TOKENS ARE ZEROED AFTER PRINTING. Not because the process is about
     * to exit, but because a struct that held a credential for the rest of a
     * long-running `serve` is a struct that ends up in a core dump. */
    memset(p.node_token, 0, sizeof p.node_token);
    memset(p.connect_token, 0, sizeof p.connect_token);
    memset(p.stop_token, 0, sizeof p.stop_token);
    fflush(stdout);
    return 0;
}

int dropssh_config(dropssh_opts *o) {
    printf("dropssh config: every setting, and where it came from\n\n");
    /* ⛔ EVERY SETTING IS PRINTED WITH ITS SOURCE, INCLUDING THE ONES THAT
     * ARE NOT IN EFFECT. A reader who wants to know why --insecure did not
     * take effect needs to see that DROPSSH_INSECURE is unset AND that the
     * flag was absent; printing only the effective value cannot express that.
     */
    printf("  %-22s %-24s %s\n", "setting", "value", "source");
    printf("  %-22s %-24s %s\n", "----------------------", "------------------------",
           "----------------------");
    printf("  %-22s %-24s %s\n", "relay", o->relay ? o->relay : "(unset)",
           o->relay ? src_flag : src_def);
    printf("  %-22s %-24s %s\n", "port", "443", src_def);
    printf("  %-22s %-24s %s\n", "path", o->path ? o->path : "(from --name)",
           o->path ? src_flag : src_def);
    printf("  %-22s %-24s %s\n", "name", o->name ? o->name : "(unset)",
           o->name ? src_flag : src_def);
    /* ⛔ THE TOKEN IS NEVER PRINTED, EVEN ITS PRESENCE IS ALL THAT MATTERS. A
     * config dump that includes a token is a config dump that ends up in a bug
     * report. */
    printf("  %-22s %-24s %s\n", "token",
           (o->token && o->token[0]) ? "(set, not printed)" : "(unset)",
           (o->token && o->token[0]) ? src_env : src_def);
    {
        const char *ph = dropssh_proxy_host();
        printf("  %-22s %-24s %s\n", "egress proxy",
               ph ? ph : "(none, direct)",
               ph ? src_env : src_def);
    }
    printf("  %-22s %-24s %s\n", "tls verification",
           dropssh_insecure() ? "DISABLED" : "on",
           o->insecure ? src_flag : src_def);
    printf("  %-22s %-24s %s\n", "doh", o->doh ? o->doh : "(built-in)",
           o->doh ? src_flag : src_def);
    printf("  %-22s %-24s %s\n", "server", o->server ? o->server : "dropbear -i -E -F",
           o->server ? src_flag : src_def);
    printf("  %-22s %-24s %s\n", "passwd", o->passwd ? o->passwd : "(unset)",
           o->passwd ? src_flag : src_def);
    printf("  %-22s %-24s %s\n", "preload", o->preload ? o->preload : "(unset)",
           o->preload ? src_flag : src_def);
    printf("  %-22s %-24s %s\n", "connect timeout", "15000 ms", src_def);
    printf("  %-22s %-24s %s\n", "once", o->once ? "yes" : "no",
           o->once ? src_flag : src_def);
    printf("  %-22s %-24s %s\n", "mint", o->generate ? "yes" : "no",
           o->generate ? src_flag : src_def);
    printf("  %-22s %-24s %s\n", "verbose", o->verbose ? "yes" : "no",
           o->verbose ? src_flag : src_def);
    printf("\n  version %s, tls backend %s\n", dropssh_version(),
           dropssh_tls_backend());
    printf("  DROPSSH_RELAY, DROPSSH_TOKEN, DROPSSH_RELAY_TOKEN, DROPSSH_PROXY,\n");
    printf("  DROPSSH_DOH and DROPSSH_INSECURE are read from the environment.\n");
    fflush(stdout);
    return 0;
}
