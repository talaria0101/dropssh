/* dropssh.h - the verbs, and the one thing that has to be true of all of them.
 *
 * THE VERB SET IS FIVE, AND EACH ONE IS A DIFFERENT DIRECTION:
 *
 *   dropssh serve    the node side, inside the cage. Dials the relay outward
 *                    and hands each paired session to a real ssh server on a
 *                    socketpair. Outbound only, so the cage needs no inbound.
 *   dropssh connect  the operator side. One byte pipe from a relay to this
 *                    process's stdin and stdout, which is what ssh's
 *                    ProxyCommand runs. This is how a person gets in.
 *   dropssh relay    both peers, for a relay dropssh operates itself. The
 *                    relay ships so a self-hosted deployment needs nothing
 *                    else, and so the e2e can prove the transport without a
 *                    network.
 *   dropssh keygen   a host key, in dropbear's own format, so the server
 *                    side has no second key implementation.
 *   dropssh doctor   what this machine can actually do, read rather than
 *                    guessed. Exits non-zero if a check failed.
 *   dropssh pair     a node token and a connect token, ready to paste, so the
 *                    operator never runs curl and puts a token in shell
 *                    history.
 *   dropssh config   every setting and where it came from: flag, environment
 *                    or built-in.
 *   dropssh version  what this binary is, including which TLS it carries and
 *                    which dropbear it was built beside.
 *
 * ⛔ NONE OF THEM NEEDS chroot, A PRIVILEGE-SEPARATION USER, OR /var. That is
 * not a preference, it is what a cage permits, and it is why the ssh server is
 * dropbear and not sshd: measured, `sshd -i` exits 0 under `sshd -t` and then
 * fails at runtime for want of a privsep chroot directory, and no setting
 * changes that.
 */
#ifndef DROPSSH_DROPSSH_H
#define DROPSSH_DROPSSH_H

#include <stddef.h>

/* The relay defaults. Both are the operator's own deployment, and both are
 * overridable on the command line. The default is what makes the tool work
 * with no configuration, which is the property worth having. */
#define DROPSSH_DEFAULT_RELAY   "tcp.ssh.relay.ajam.dev"
#define DROPSSH_DEFAULT_FORWARD "/connect/railway"

typedef struct {
    const char *relay;        /* relay host */
    int         port;         /* 443 */
    const char *path;         /* request target */
    const char *token;        /* X-Relay-Token, or NULL */
    const char *name;         /* reverse node name */
    const char *server;       /* the ssh server command for `serve` */
    const char *hostkey;
    const char *authkeys;
    const char *shell;        /* login shell override for a cage with no /etc/passwd */
    const char *passwd;       /* SANDHOME_PASSWD for a cage with no /etc/passwd */
    const char *preload;      /* LD_PRELOAD for a cage whose shims must reach the server */
    const char *user;
    const char *doh;          /* DoH endpoint, or NULL for the default */
    int         insecure;
    int         verbose;
    int         connect_ms;
    int         bound_ms;      /* connect: how long to wait for the node's `ready`.
                                * 0 disables the bound, which the gate needs so a
                                * build with the bound DELETED can be shown to
                                * fail. Nothing in the suite passes it. */
    int         once;         /* serve: one session then exit */
    int         generate;     /* connect: ask the relay for a token first */
    int         json;
} dropssh_opts;

/* ⛔ HOW LONG AN OPERATOR WAITS FOR THE NODE'S `ready`. Defined here because
 * `main.c` has to print it as the default for --bound-ms, and a default shown
 * in --help that is not the number in the code is how "it ignored my flag"
 * starts. `connect.c` is the only user.
 *
 * Six times the relay's own ten-second open timeout, so a slow but working node
 * is not cut off and a relay that does close normally ends the wait first. It
 * exists for the relay that never closes, because `connect` is an ssh
 * ProxyCommand: an operator with no message has no way out and ssh has no
 * timeout of its own. Overridable so that its ABSENCE can be demonstrated; see
 * `tests/mux-probe.py` case 8 and U1 in `docs/relay-issues.md`. */
#define DROPSSH_READY_BOUND_MS 60000

int dropssh_serve(dropssh_opts *o);
int dropssh_connect(dropssh_opts *o);
int dropssh_relay_main(int argc, char **argv);
int dropssh_keygen(const char *type, const char *file, int bits);
int dropssh_version_cmd(void);
int dropssh_doctor(dropssh_opts *o);
int dropssh_pair(dropssh_opts *o);
int dropssh_config(dropssh_opts *o);

#endif /* DROPSSH_DROPSSH_H */
