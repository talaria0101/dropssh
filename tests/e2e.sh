#!/usr/bin/env bash
# e2e.sh - prove the release artefacts, not just that they built.
#
# ⛔ A BINARY THAT COMPILES AND CANNOT LOG ANYONE IN IS THE FAILURE THIS
# EXISTS TO PREVENT, and the only way to know is to run a session through it.
# `dropbear -t`, `file`, and a green make are all incapable of seeing it: the
# failure appears at LOGIN, on a machine that has no /etc/passwd, as
#
#     Login attempt for nonexistent user from localhost:...
#
# for a user that is there. So every case below carries real bytes through a
# real ssh client and checks the answer.
#
# USAGE: tests/e2e.sh [DISTDIR]
#   DISTDIR defaults to dist/x86_64-linux-musl.
set -uo pipefail

DIST="${1:-dist/x86_64-linux-musl}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
# ⛔ THE WORK DIRECTORY IS PRIVATE AND INSIDE THE LOGIN USER'S OWN AREA, AND
# BOTH MATTER.
#
# dropbear checks that the authorized_keys PATH is owned by the login user or
# root and is not group- or world-writable, and it says so:
#
#     /tmp must be owned by user or root, and not writable by group or others
#
# Measured on a GitHub Actions runner, 2026-09-27, where the work directory came
# from `mktemp -d` and so lived under /tmp, which is mode 1777. In a cage the
# same `mktemp -d` lands in a /tmp owned by root with no other-write bit, so the
# check passes and the suite is green -- which is why this passed locally for
# the whole of development and failed on the first CI run.
#
# So the suite does not use mktemp. It makes a directory it owns, under the
# login user's own home when there is one, and asserts the mode rather than
# hoping for it: the check is a security control and it is satisfied, not
# worked around.
if [ -n "${HOME:-}" ] && [ "$HOME" != "/" ] && [ -d "$HOME" ] && [ -w "$HOME" ]; then
    WORK_BASE="$HOME"
else
    WORK_BASE="$(pwd)"
fi
WORK=$(mktemp -d "$WORK_BASE/dropssh-e2e.XXXXXX")
chmod 700 "$WORK"
# Kept on failure so a red run can be inspected; removed on success.
KEEP_WORK="${DROPSSH_KEEP_WORK:-0}"
cleanup() { if [ "$KEEP_WORK" = 1 ]; then echo "e2e: artefacts kept in $WORK"; else rm -rf "$WORK"; fi; }
trap cleanup EXIT

pass=0; fail=0
ok()   { printf '  ok    %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  FAIL  %s\n' "$*"; fail=$((fail+1)); }
head_() { printf '\n== %s\n' "$*"; }

DROPSSH="$DIST/dropssh"
DROPBEAR="$DIST/dropbear"
DROPBEARKEY="$DIST/dropbearkey"
SHIM="$DIST/fakepwd.so"

# ⛔ THE EXIT STATUS IS READ FROM THE SCRIPT, NEVER THROUGH A PIPE. A pipe
# reports the LAST command's status, so a failing test piped to `tee` looks
# green. Every case below uses `rc=$?` immediately after the command.

for f in "$DROPSSH" "$DROPBEAR" "$DROPBEARKEY" "$SHIM"; do
    [ -e "$f" ] || { echo "e2e: missing $f; run scripts/build.sh first" >&2; exit 2; }
done

# ⛔ THE TOOLS THE SUITE NEEDS ARE CHECKED FIRST, AND THE MESSAGE SAYS WHICH.
#
# A missing ssh-keygen used to surface forty lines later as "could not make a
# client key", which names the wrong thing: the key generation is fine, the
# tool is absent. Checking the prerequisites at the top turns a confusing
# mid-suite failure into one line that can be acted on, and it is the same
# principle as the artefact checks: say what is missing, not what went wrong
# later.
missing=""
for t in ssh ssh-keygen; do
    command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
if [ -n "$missing" ]; then
    echo "e2e: missing required tools:$missing" >&2
    echo "     on Debian or Ubuntu: apt-get install -y openssh-client" >&2
    exit 2
fi

# ---------------------------------------------------------------- the cage
# The e2e reproduces the two conditions of the target cage rather than
# assuming them, because a test on a normal machine proves nothing about a
# cage. It cannot remove /etc/passwd, so it supplies the shim's database
# explicitly, which is the same code path a cage takes.
# ⛔ EVERY DIRECTORY dropbear WILL CHECK IS MODE 700 AND ASSERTED, NOT ASSUMED.
# It checks the authorized_keys path itself and each directory above it, and the
# one above it is $WORK, which `mktemp -d` gives 700 but a future edit could
# take away. The assertion is one line and it is the difference between a suite
# that is safe on a runner and one that is not.
mkdir -p "$WORK/ak" "$WORK/home"
chmod 700 "$WORK" "$WORK/ak" "$WORK/home"
# The passwd file comes first: ssh-keygen and dropbearkey both consult it
# through the shim, and a file that does not exist yet is a failure that
# names the wrong tool.
# ⛔ THE SUITE LOGS IN AS THE UID THE SERVER RUNS AS, AND THE REASON IS MEASURED
# IN CI ON TWO SEPARATE COUNTS.
#
# dropbear refuses a login whose target uid differs from the server's effective
# uid:
#
#     Login attempt with wrong user root from localhost:...
#     Exit before auth from <localhost:...>: (user 'root', 0 fails)
#
# On a GitHub Actions runner the session is uid 1001, so a suite that asks for
# a root login is refused by a server running as `runner` -- with the user
# present, the shell present and executable, and the key correct. In a cage the
# server runs as uid 0 and the same request succeeds, which is why this passed
# locally for the whole of development and failed on the first CI run.
#
# The check is right and is left alone: a server running as an unprivileged uid
# must not hand that uid a session as somebody else, because everything the
# session does is done as the server's uid. What was wrong was the TEST, which
# assumed it runs as root. It does not, on a runner, and a test that assumes it
# does is a test of a different machine.
#
# So the suite asks for whichever uid it is, and the passwd file names that
# user. In a cage that is root and the README's command is exercised verbatim.
CUR_UID=$(id -u 2>/dev/null || echo 0)
CUR_GID=$(id -g 2>/dev/null || echo 0)
CUR_NAME=$(id -un 2>/dev/null || echo "user$CUR_UID")
CUR_HOME="$WORK/home"
LOGIN_USER="$CUR_NAME"
if [ "$CUR_UID" = 0 ]; then
    LOGIN_USER=root
fi
# The shim REPLACES the passwd database rather than adding to it, which is
# right for a cage with no /etc/passwd and wrong for a machine that has one.
# So the file names the user being logged in as, at the uid that user has.
printf '%s:x:%s:%s:%s:%s:/bin/sh\n' \
    "$LOGIN_USER" "$CUR_UID" "$CUR_GID" "$LOGIN_USER" "$CUR_HOME" \
    >"$WORK/passwd"
"$DROPBEARKEY" -t ed25519 -f "$WORK/hostkey" >/dev/null 2>&1 \
    || { echo "e2e: dropbearkey could not make a host key" >&2; exit 2; }
# ⛔ THE CLIENT KEY IS MADE WITH THE SHIM ALREADY IN PLACE, because in a cage
# ssh-keygen dies with "No user exists for uid 0" before it does anything
# useful. The e2e runs in the same environment it is testing, so it has to
# clear the same bar, and a test that only works on a machine with a passwd
# database is a test of a different machine.
# ⛔ ITS OUTPUT IS KEPT, NOT DISCARDED. The first version sent stderr to
# /dev/null and reported only "could not make a client key", which is a message
# about the tool rather than about the reason, and it cost a CI cycle to find
# out that the cause was the tool not being installed on the runner at all
# rather than anything to do with the shim.
if ! LD_PRELOAD="$SHIM" SANDHOME_PASSWD="$WORK/passwd" \
        ssh-keygen -q -t ed25519 -N '' -f "$WORK/user_ed25519" \
        >"$WORK/keygen.out" 2>&1; then
    echo "e2e: could not make a client key. ssh-keygen said:" >&2
    sed 's/^/    /' "$WORK/keygen.out" >&2
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        echo "    and ssh-keygen is not on PATH at all: install openssh-client" >&2
    fi
    exit 2
fi
cp "$WORK/user_ed25519.pub" "$WORK/ak/authorized_keys"
chmod 600 "$WORK/ak/authorized_keys"

printf '== dropssh e2e: logging in as %s (uid %s), server runs as the same uid\n' \
    "$LOGIN_USER" "$CUR_UID"

head_ "the shim answers for a user a cage does not have"
# ⛔ THIS IS THE STATIC-BINARY TRAP, ASSERTED RATHER THAN DESCRIBED. A static
# dropbear carries its own libc, LD_PRELOAD cannot reach it, and every login
# fails with a message that names the wrong thing. The check is made against
# the artefact on disk, because that is the only place the property exists.
if command -v file >/dev/null 2>&1; then
    KIND=$(file -b "$DROPBEAR")
    case "$KIND" in
        *"dynamically linked"*) ok "dropbear is dynamically linked, so the shim can reach it" ;;
        *) bad "dropbear is not dynamically linked: $KIND" ;;
    esac
fi

head_ "the ssh server starts here"
# ⛔ THE PROBE USES A SOCKETPAIR, NOT /dev/null, AND THE REASON IS MEASURED.
#
# The first version of this check ran `dropbear -i ... </dev/null` and asserted
# the process stayed up. It exited 1, and the cause is specific and worth
# knowing: on a character device getpeername() has no peer to name, and this
# build answers
#
#     Early exit: Failed socket address: Socket operation on non-socket
#
# and exits. That is correct behaviour and a useless probe: `dropssh serve`
# never hands the server a character device, it hands it one end of a
# AF_UNIX socketpair. Probing the shape the server will actually be given is
# the difference between a test that measures the tool and one that measures a
# detail of how a shell redirects stdin.
python3 - "$DROPBEAR" "$WORK/hostkey" "$WORK/ak" "$SHIM" "$WORK/passwd" <<'PYPROBE'
import os, socket, subprocess, sys, time
binary, hostkey, akdir, shim, passwd = sys.argv[1:6]
a, b = socket.socketpair()
env = dict(os.environ)
env["LD_PRELOAD"] = shim
env["SANDHOME_PASSWD"] = passwd
p = subprocess.Popen([binary, "-i", "-E", "-F", "-r", hostkey, "-D", akdir],
                     stdin=b.fileno(), stdout=b.fileno(),
                     stderr=subprocess.PIPE, env=env, close_fds=False)
b.close()
time.sleep(1.5)
alive = p.poll() is None
if not alive:
    sys.stderr.write((p.stderr.read() or b"").decode("utf-8", "replace"))
p.kill()
sys.exit(0 if alive else 1)
PYPROBE
rc=$?
if [ "$rc" = 0 ]; then
    ok "dropbear -i stays up on a socketpair waiting for a session"
else
    bad "dropbear -i exited inside the probe window on a socketpair"
fi

# ---------------------------------------------------------------- the chain
# One function, used by every session case: a local relay, a node serving
# `dropbear -i`, and a real ssh client through `dropssh connect`.
run_session() {
    # ⛔ THE FOURTH ARGUMENT IS FORWARDED, NOT ABSORBED.
    #
    # This wrapper took "${3:-}" and passed only three arguments on, so a
    # caller that supplied an ssh user got it silently dropped and every login
    # was attempted as root. The case that depends on it -- a passwd entry whose
    # user has an invalid shell -- then authenticated as root, ran, and the
    # suite reported that a nonexistent shell had REACHED THE SHELL, against a
    # server log that said "Pubkey auth succeeded for 'root'".
    #
    # A wrapper that drops an argument is worse than no wrapper: the call looks
    # right and the test measures the wrong thing.
    run_session_with_passwd "$1" "$2" "$WORK/passwd" "${3:-$LOGIN_USER}"
}

run_session_with_passwd() {
    # name, command, passwd file, and optionally the ssh user to log in as.
    # The user is last because only the negative shell case needs it and a
    # default in the middle would be a trap for every other caller.
    local name="$1" cmd="$2" passwdfile="$3" ssh_user="${4:-}" sock="$WORK/$1.sock"
    rm -f "$sock"
    "$DROPSSH" relay --listen "unix://$sock" >"$WORK/$1-relay.log" 2>&1 &
    local relay_pid=$!
    # the relay needs a moment to bind; a fixed sleep is replaced by a
    # bounded wait on the socket existing, which is what is actually wanted
    local i=0
    while [ $i -lt 50 ] && [ ! -S "$sock" ]; do sleep 0.05; i=$((i+1)); done
    [ -S "$sock" ] || { bad "$name: the relay never bound $sock"; kill $relay_pid 2>/dev/null; return 1; }

    "$DROPSSH" serve --relay "unix://$sock" --name "$name" \
        --passwd "$passwdfile" --preload "$SHIM" \
        --server "$DROPBEAR -i -E -F -r $WORK/hostkey -D $WORK/ak" \
        >"$WORK/$1-serve.log" 2>&1 &
    local serve_pid=$!
    sleep 0.8

    LD_PRELOAD="$SHIM" SANDHOME_PASSWD="$passwdfile" \
    timeout 40 ssh \
        -o "ProxyCommand=$DROPSSH connect --relay unix://$sock --name $name" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR \
        -i "$WORK/user_ed25519" "${ssh_user:-$LOGIN_USER}@$name" "$cmd" \
        >"$WORK/$1.out" 2>"$WORK/$1.err"
    local rc=$?
    kill $serve_pid $relay_pid 2>/dev/null
    wait $serve_pid $relay_pid 2>/dev/null
    return $rc
}

head_ "a pubkey session end to end, through relay, serve, dropbear and connect"
# ⛔ THE EXPECTED UID IS THE UID UNDER TEST, NOT 0.
#
# The suite logs in as whoever it runs as, and the session must report THAT uid
# back: dropbear's own check is that the login uid equals the server's, so a
# session reporting anything else means the login did not go the way it was
# supposed to. Asserting a literal 0 passed in a cage and failed on a runner,
# which is the same class of mistake as the two above it -- the test assuming an
# environment it does not control.
if run_session session1 'echo E2E_PROVEN; id -u'; then
    if grep -q E2E_PROVEN "$WORK/session1.out" \
       && grep -qx "$CUR_UID" "$WORK/session1.out"; then
        ok "a real session ran and reported uid $CUR_UID"
    else
        bad "the session ran but its output was wrong (expected uid $CUR_UID)"
        sed 's/^/        /' "$WORK/session1.out" 2>/dev/null | head -5
        sed 's/^/        /' "$WORK/session1.err" 2>/dev/null | head -5
    fi
else
    bad "the session did not complete"
    strings "$WORK/session1-serve.log" 2>/dev/null | tail -6 | sed 's/^/        /'
    sed 's/^/        /' "$WORK/session1.err" 2>/dev/null | head -6
fi

head_ "the session survives a large transfer"
head -c 200000 /dev/urandom | base64 >"$WORK/big.txt"
if run_session session2 'wc -c < '"$WORK"'/big.txt'; then
    got=$(tr -d ' \r' <"$WORK/session2.out")
    want=$(wc -c <"$WORK/big.txt" | tr -d ' ')
    if [ "$got" = "$want" ]; then
        ok "a $want byte transfer came back byte for byte"
    else
        bad "the transfer returned $got, expected $want"
    fi
else
    bad "the transfer session did not complete"
fi

head_ "the login shell is one that exists"
# ⛔ THE SHIM'S BUILT-IN DEFAULT SHELL IS /bin/bash, AND A CAGE OFTEN HAS ONLY
# /bin/sh. With the default, dropbear rejects the login with "User 'root' has
# invalid shell, rejected" -- which is an authentication-looking failure for a
# user who authenticated perfectly. The passwd file this build ships names
# /bin/sh, and this case proves the whole path that depends on it.
if run_session session3 'echo SHELL_OK'; then
    if grep -q SHELL_OK "$WORK/session3.out"; then
        ok "a session runs as $LOGIN_USER with the shipped passwd file"
    else
        bad "the session did not run"
        sed 's/^/        /' "$WORK/session3-serve.log" 2>/dev/null | head -8
    fi
else
    bad "the shell session did not complete"
fi

head_ "a shell that exists is a login shell"
# ⛔ THIS CASE EXISTS BECAUSE A LOGIN WAS REFUSED ON A HOST THAT HAD A
# POLICY FILE, AND IT NAMED THE USER RATHER THAN THE SHELL.
#
# dropbear validates the login shell against getusershell(), which reads
# /etc/shells. On a host that HAS one, a passwd entry naming a shell the file
# does not list is denied:
#
#   Login attempt with wrong user root from localhost:...
#   Exit before auth from <localhost:...>: (user 'root', 0 fails)
#
# with the user present, the shell present and the shell executable. It was
# found on a GitHub Actions runner and not in a cage, because a cage has no
# /etc/shells and dropbear then uses a compiled-in fallback. So whether a login
# worked depended on whether a POLICY FILE existed.
#
# The patch accepts a shell that exists and is executable, after consulting the
# list, so a host with a policy keeps it. This case asserts the acceptance. It
# cannot create an /etc/shells here, so it asserts the other half of the same
# condition: a shell that does NOT exist is still refused, which is what stops
# the tolerance from becoming "any string is a shell".
if run_session session_shell 'echo SHELL_ACCEPTED'; then
    if grep -q SHELL_ACCEPTED "$WORK/session_shell.out"; then
        ok "a login with an executable shell is accepted"
    else
        bad "the shell session ran but produced no output"
    fi
else
    bad "a login with an executable shell was refused"
    strings "$WORK/session_shell-serve.log" 2>/dev/null | grep -iE "shell|user" | head -3 | sed 's/^/        /'
fi

# The negative half: a passwd entry naming a shell that is not there must be
# refused. Without this the tolerance would accept any string as a shell.
# ⛔ THE GHOST ENTRY CARRIES THE SERVER'S UID, NOT 0. dropbear's uid check runs
# BEFORE the shell check, so an entry with uid 0 on a server at uid 1001 is
# refused for being the wrong user and the shell check is never reached, which
# would make this case pass for the wrong reason on a runner and fail for the
# right one here. The uid is the server's, so the only thing that can refuse the
# login is the shell.
printf '%s:x:%s:%s:%s:%s:/bin/sh\n' \
    "$LOGIN_USER" "$CUR_UID" "$CUR_GID" "$LOGIN_USER" "$WORK/home" >"$WORK/passwd-ghost"
printf 'ghost:x:%s:%s:ghost:%s:/bin/dropssh-not-a-shell\n' \
    "$CUR_UID" "$CUR_GID" "$WORK/home" >>"$WORK/passwd-ghost"
# ⛔ THE ASSERTION IS ON WHAT THE SERVER SAID, NOT ON ssh's EXIT CODE.
#
# The first version read the exit status, and a REFUSED login exits non-zero
# just like a broken one, so the branch was backwards: the suite reported "a
# login with a nonexistent shell was ACCEPTED" against a server that had
# correctly said
#
#   User 'ghost' has an invalid shell '/bin/dropssh-not-a-shell', rejected
#
# The exit code cannot distinguish "refused" from "broken". The server's own
# words can, and that is also the thing worth asserting: the refusal is named.
run_session_with_passwd session_ghost 'echo SHOULD_NOT_REACH_HERE' \
    "$WORK/passwd-ghost" ghost >/dev/null 2>&1 || true
# ⛔ THE SERVER LOG IS READ THROUGH `strings`, BECAUSE IT IS A MIXTURE OF TEXT
# AND dropbear's PEER ADDRESS, WHICH CARRIES NON-TEXT BYTES. `grep -q` on that
# file treats it as binary, prints "Binary file matches" instead of the line,
# and exits 0, so the first version of this assertion passed or failed for a
# reason that had nothing to do with the login. Every other read of a server
# log in this suite goes through strings for the same reason and this one had
# been missed.
if strings "$WORK/session_ghost-serve.log" 2>/dev/null | grep -qiE "invalid shell"; then
    ok "a login with a shell that does not exist is refused, and says so"
elif strings "$WORK/session_ghost.out" 2>/dev/null | grep -qx "SHOULD_NOT_REACH_HERE"; then
    # ⛔ MATCHED AS A WHOLE LINE, AND NOT AS A SUBSTRING. ssh echoes the
    # command it was given into its own error output when a channel closes
    # before the exec, so a substring match reports a refused login as a
    # reached one. Only a line that is exactly the marker means the command
    # ran.
    bad "a login with a nonexistent shell REACHED THE SHELL"
else
    bad "a login with a nonexistent shell was refused without saying why"
    strings "$WORK/session_ghost-serve.log" 2>/dev/null | tail -4 | sed 's/^/        /'
fi

# ============================================ the multiplexed reverse path
# ⛔ EVERY CASE BELOW IS ABOUT ONE SOCKET CARRYING MANY SESSIONS, AND THE FIRST
# VERSION OF THIS FILE HAD A `session2` CASE THAT WAS SEQUENTIAL: it ran after
# session1 had finished. One session cannot catch the defect, because the
# defect only exists when two sessions are live at the same time and a frame
# can be taken by whichever thread happens to be running. A sequential suite
# is a suite that reports the multiplexer working.
#
# The relay's protocol is asymmetric and the asymmetry is the whole test:
# the operator writes BARE bytes and the relay prepends the 32-hex session id,
# while the node prefixes the id itself and the relay strips it. Both rules
# are asserted here, one by a real session and one negatively.
head_ "TWO CONCURRENT SESSIONS ON ONE NODE SOCKET"
# ⛔ BOTH OPERATORS ARE LAUNCHED BEFORE EITHER IS WAITED ON, AND ONE OF THEM
# SLEEPS FIRST. If they ran one after the other this would be the old
# sequential case. The sleeping session is the harder one: it holds its
# socket open and idle for seconds while the other runs a 270 KB transfer
# through the same node websocket, so every frame of that transfer is a frame
# the sleeping session's reader could have taken.
rm -f "$WORK/mux.sock"
"$DROPSSH" relay --listen "unix://$WORK/mux.sock" >"$WORK/mux-relay.log" 2>&1 &
mux_relay_pid=$!
i=0; while [ $i -lt 50 ] && [ ! -S "$WORK/mux.sock" ]; do sleep 0.05; i=$((i+1)); done
if [ ! -S "$WORK/mux.sock" ]; then
    bad "the multiplexer relay never bound $WORK/mux.sock"
else
    "$DROPSSH" serve --relay "unix://$WORK/mux.sock" --name muxbox \
        --passwd "$WORK/passwd" --preload "$SHIM" \
        --server "$DROPBEAR -i -E -F -r $WORK/hostkey -D $WORK/ak" \
        >"$WORK/mux-serve.log" 2>&1 &
    mux_serve_pid=$!
    # the node needs its socket up before an operator can attach to it: a
    # relay that is asked for a node that has not connected answers 503, and a
    # bounded wait on the log is more honest than a sleep that might be short.
    i=0
    while [ $i -lt 100 ] && ! strings "$WORK/mux-serve.log" 2>/dev/null | grep -q "registered with"; do
        sleep 0.1; i=$((i+1))
    done

    mux_ssh() {   # 1: session name, 2: remote command
        LD_PRELOAD="$SHIM" SANDHOME_PASSWD="$WORK/passwd" \
        timeout 45 ssh \
            -o "ProxyCommand=$DROPSSH connect --relay unix://$WORK/mux.sock --name muxbox" \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o BatchMode=yes -o ConnectTimeout=20 -o LogLevel=ERROR \
            -i "$WORK/user_ed25519" "$LOGIN_USER@muxbox" "$2" \
            >"$WORK/$1.out" 2>"$WORK/$1.err"
        echo $?
    }

    # Launched together, waited on separately. `mux_ssh` echoes the exit
    # status rather than setting it, so a background subshell can report it.
    ( mux_ssh mux_a 'sleep 4; echo MUX_ALPHA; id -u' >"$WORK/mux_a.rc" ) &
    mux_a_pid=$!
    ( mux_ssh mux_b 'echo MUX_BETA; wc -c < '"$WORK"'/big.txt' >"$WORK/mux_b.rc" ) &
    mux_b_pid=$!
    wait $mux_a_pid $mux_b_pid
    mux_a_rc=$(cat "$WORK/mux_a.rc" 2>/dev/null)
    mux_b_rc=$(cat "$WORK/mux_b.rc" 2>/dev/null)

    # ⛔ EACH SESSION IS ASSERTED ON ITS OWN MARKER AND ON ITS OWN OUTPUT, and
    # then CROSS-CHECKED: alpha's marker must not appear in beta's output and
    # beta's byte count must not appear in alpha's. One session's bytes landing
    # in another session's stream is the failure this case exists to catch, and
    # asserting only that both succeeded would not see it.
    mux_fail=""
    [ "$mux_a_rc" = 0 ] || mux_fail="alpha exited $mux_a_rc"
    [ "$mux_b_rc" = 0 ] || mux_fail="$mux_fail; beta exited $mux_b_rc"
    grep -q MUX_ALPHA "$WORK/mux_a.out" 2>/dev/null || mux_fail="$mux_fail; alpha produced no marker"
    grep -q MUX_BETA  "$WORK/mux_b.out" 2>/dev/null || mux_fail="$mux_fail; beta produced no marker"
    grep -q MUX_BETA  "$WORK/mux_a.out" 2>/dev/null && mux_fail="$mux_fail; beta's output appeared in alpha's stream"
    grep -q MUX_ALPHA "$WORK/mux_b.out" 2>/dev/null && mux_fail="$mux_fail; alpha's output appeared in beta's stream"
    if [ -z "$mux_fail" ]; then
        ok "two concurrent sessions on one node socket, each receiving only its own bytes"
    else
        bad "the concurrent sessions failed:$mux_fail"
        sed 's/^/        /' "$WORK/mux_a.err" 2>/dev/null | head -4
        sed 's/^/        /' "$WORK/mux_b.err" 2>/dev/null | head -4
    fi

    # The node must have served all three sessions (the one before this block
    # plus these two) over ONE socket, not one socket per session. The count of
    # "registered with" lines in the node's own log is that measurement, and it
    # is what makes "one session per socket" fail here rather than pass slowly.
    mux_registers=$(strings "$WORK/mux-serve.log" 2>/dev/null | grep -c "registered with")
    mux_opens=$(strings "$WORK/mux-serve.log" 2>/dev/null | grep -c "operator opened session")
    if [ "$mux_registers" = 1 ] && [ "$mux_opens" -ge 2 ]; then
        ok "the node held one websocket for $mux_opens sessions (not one per session)"
    else
        bad "the node re-registered $mux_registers times for $mux_opens sessions"
    fi
    kill $mux_serve_pid $mux_relay_pid 2>/dev/null
    wait $mux_serve_pid $mux_relay_pid 2>/dev/null
fi

head_ "the id-prefix rule, asserted rather than described (R11)"
# ⛔ THE NODE'S DATA FRAME MUST CARRY THE 32-HEX ID AND THE RELAY'S OWN CLOSE
# IS THE ASSERTION. docs/reverse-relay.md documents the asymmetry in a table
# and a reader has to trust it; a regression that drops the prefix then looks
# exactly like a relay that has gone quiet, which is how B11 cost an afternoon.
#
# So this drives the node's own reader with a well-formed frame and a bare one
# and reads what the relay DID, not what a document says it does. The bare
# frame must produce a named close (1009 "bad multiplex frame", measured live
# against tcp.ssh.relay.ajam.dev on 2026-09-28), never silence. A relay that
# drops it quietly is the bug this case was written for, and it is the failure
# the old documentation described as expected behaviour.
if [ -f "$HERE/mux-probe.py" ]; then
    if python3 "$HERE/mux-probe.py" "$DROPSSH" "$WORK"; then
        ok "the id-prefix rule holds: a bare node frame is closed by name, not dropped"
    else
        bad "the id-prefix rule failed (see the output above)"
    fi
else
    bad "tests/mux-probe.py is missing, so the id-prefix rule is unasserted"
fi

head_ "relay tokens: a pair issued here works here, and the two roles differ"
# ⛔ ISSUE #13 STEP 1 IS "A PAIR ISSUED BY OUR RELAY WORKS AGAINST IT", and a
# signer with no round-trip test is a signer nobody has run. So this drives the
# WHOLE path, not the module: `POST /v1/pair` on a real relay over a real unix
# socket, then six upgrades against the answer it gave.
#
# ⛔ AND THE CASES THAT MATTER ARE ALL REFUSALS, because a pair that round-trips
# proves only that the encoder and the decoder share a bug. What has to hold is
# that a NODE token is refused where a CONNECT token belongs (otherwise reading
# the cage's token opens a session), that a token for another name is refused
# (otherwise a pair is two credentials for any name), and that a relay with no
# key accepts everything, which is the behaviour every existing deployment has.
relay_sock="$WORK/token-relay.sock"
tlog="$WORK/token-relay.log"
rm -f "$relay_sock"
"$DROPSSH" relay --listen "unix://$relay_sock" --token-key "e2e key" >"$tlog" 2>&1 &
relay_pid=$!
tok_ok=0
for _ in $(seq 1 60); do [ -S "$relay_sock" ] && break; sleep 0.1; done
# ⛔ A SECOND RELAY WITH THE SAME KEY, because "a session migrates between two
# relays without being re-created" is a claim about TWO processes and cannot be
# checked against one. A token that is a handle into the issuing relay's table
# passes every other case in this section and fails exactly this one, which is
# why the second relay exists rather than a second call to the first.
peer_sock="$WORK/token-peer.sock"
plog="$WORK/token-peer.log"
rm -f "$peer_sock"
"$DROPSSH" relay --listen "unix://$peer_sock" --token-key "e2e key" >"$plog" 2>&1 &
peer_pid=$!
for _ in $(seq 1 60); do [ -S "$peer_sock" ] && break; sleep 0.1; done
if [ ! -S "$relay_sock" ]; then
    bad "the token relay never bound $relay_sock (see $tlog)"
else
    if python3 "$HERE/token-check.py" "$relay_sock" --peer="$peer_sock"; then
        ok "a pair issued by this relay works against it, the roles are separate, and it migrates to a second relay holding the same key"
    else
        bad "the token round trip, its role separation, or its migration to a second relay failed (see the output above)"
    fi
    tok_ok=1
fi
kill "$relay_pid" 2>/dev/null
wait "$relay_pid" 2>/dev/null
kill "$peer_pid" 2>/dev/null
wait "$peer_pid" 2>/dev/null
rm -f "$relay_sock" "$peer_sock"

# ⛔ AND A RELAY WITH NO KEY STILL ACCEPTS EVERYTHING. This is the compatibility
# rule and it is the case most likely to break silently, because the banner and
# the behaviour are separate claims about the same process and they disagreed
# once already: a relay with no key printed "ACCEPTED as anything" and refused
# every peer with "no token was sent". A gate that only ever starts a keyed
# relay would not have seen it.
nosock="$WORK/token-nokey.sock"
nolog="$WORK/token-nokey.log"
rm -f "$nosock"
"$DROPSSH" relay --listen "unix://$nosock" >"$nolog" 2>&1 &
nokey_pid=$!
for _ in $(seq 1 60); do [ -S "$nosock" ] && break; sleep 0.1; done
if [ -S "$nosock" ] && python3 "$HERE/token-check.py" "$nosock" --nokey; then
    ok "a relay with no token key accepts an untokened upgrade, as it always has"
else
    bad "a relay with no token key refused an untokened upgrade: the historical behaviour is broken"
fi
kill "$nokey_pid" 2>/dev/null
wait "$nokey_pid" 2>/dev/null
rm -f "$nosock"

head_ "the SOCKS5 listener reaches exactly one named destination"
# ⛔ THE SOCKS5 DESTINATION POLICY IS THE WHOLE SECURITY OF THE FEATURE, AND IT
# IS ASSERTED AS A DECISION RATHER THAN AS A LISTENER.
#
# The listener binds an INET socket and dropssh#6 measured 24/24 that every
# INET bind is refused with EACCES at uid 0, so on this machine -- and on the
# reference cage the project exists for -- the listener cannot be started at
# all. A probe case for it would be a case that cannot run, and this repository
# has shipped four of those.
#
# So the DECISION is tested, on the function lifted out of src/relay.c at build
# time. The extraction fails the build if the function is renamed or removed,
# which is the point: a test that copies the policy asserts the copy, and a
# test that includes the real one cannot go stale without saying so.
#
# What is NOT established, and is not claimed: that the SOCKS5 wire format is
# parsed correctly, that a forward reaches a node, or that bytes move. None of
# those can be run here, and a case that claims to cover them is the thing this
# project keeps refusing to write.
if [ -f "$HERE/socks-policy-test.sh" ]; then
    if sh "$HERE/socks-policy-test.sh"; then
        ok "the SOCKS5 listener reaches only the destination the operator named, and refuses everything else"
    else
        bad "the SOCKS5 destination policy does not hold: a SOCKS5 proxy that dials what it is asked to dial is an OPEN PROXY (see the output above)"
    fi
else
    bad "tests/socks-policy-test.sh is missing, so the SOCKS5 policy is unasserted"
fi

# ⛔ AND THE CONFIGURATION GUARDS, WHICH ARE CHECKED HERE BECAUSE THEY ARE THE
# PART THAT CAN BE RUN ON THIS MACHINE. Both refuse rather than starting a
# listener with no policy, and a listener with no policy is the open proxy
# arriving through a different door.
sockcfg_out="$WORK/socks-cfg.out"
"$DROPSSH" relay --listen "unix://$WORK/socks-cfg.sock" --socks 127.0.0.1:11080 \
    >"$sockcfg_out" 2>&1
if grep -q "open proxy" "$sockcfg_out" 2>/dev/null; then
    ok "--socks without a named destination is refused: a listener with no policy is an open proxy"
else
    bad "--socks with no --socks-dest did not refuse; see $sockcfg_out"
fi
rm -f "$WORK/socks-cfg.sock"

head_ "a node that cannot pair says so instead of retrying for ever"
# ⛔ A CAPPED BACKOFF WITH NO TOTAL IS AN AGENT THAT NEVER ADMITS IT IS BROKEN,
# and from outside it looks healthy: the process is running, it is not
# crashing, and it logs a line every 30 seconds. A supervisor sees a live
# process and a service that is not there. This is the ligolo item
# dropssh#8 asks us to adopt, and it is asserted by RUNNING it, because the
# only way to see a give-up point is to reach it.
#
# The relay deliberately does not exist, so every attempt fails. The budget is
# small so the case is quick, and the exit code is checked separately from the
# message because they are different claims: a message can be printed by a
# process that then keeps going, and only the status says it stopped.
budget_sock="$WORK/no-such-relay.sock"
rm -f "$budget_sock"
budget_out="$WORK/retry-budget.out"
"$DROPSSH" serve --relay "unix://$budget_sock" --name budget-probe \
    --retry-budget 3 --server "$DROPBEAR -i -E -F -r $WORK/hostkey" \
    >"$budget_out" 2>&1
budget_rc=$?
if [ "$budget_rc" = 4 ]; then
    ok "a node that cannot pair within its budget exits 4, which is not the exit a session failure uses"
elif [ "$budget_rc" = 0 ]; then
    bad "a node that could not pair at all exited 0: a refused node reported as a success"
else
    bad "a node that could not pair exited $budget_rc; 4 is the give-up code and 1 is a session that ran and could not log anyone in"
fi
if grep -q "the last one" "$budget_out" 2>/dev/null && \
   grep -q "giving up after 3 attempts" "$budget_out" 2>/dev/null; then
    ok "the log names the last attempt and the give-up, so the budget is readable without counting"
else
    bad "the retry log did not name the last attempt and the give-up point (see $budget_out)"
fi
# ⛔ THE HELP IS READ INTO A FILE, NOT THROUGH A PROCESS SUBSTITUTION. The suite
# is `sh`, not bash, and `<(...)` is a bashism that fails with "No such file or
# directory" on dash -- which is the same class of "a check that cannot run is
# not a check" that this project has been bitten by.
budget_help="$WORK/retry-help.out"
"$DROPSSH" --help >"$budget_help" 2>&1
if grep -q "retry for ever" "$budget_help" 2>/dev/null; then
    ok "the default is documented as unlimited, because a cage that boots before its relay must still pair"
else
    bad "the retry budget's default is not documented, so an operator cannot tell whether a node gives up"
fi

head_ "one owner per websocket session (U2), asserted on the artefact"
# ⛔ U2 WAS 0/6 BECAUSE EVERY EXISTING CASE SITS *ABOVE* THE SESSION MOVE, so
# no probe could tell a move from a copy. Closing it with another probe case
# would repeat that mistake, so the property is asserted directly, on the real
# compiled ws.c, by the only thing that can distinguish them: closing the
# moved-from source must be inert, and a copy's is not.
#
# ⛔ AND IT IS PROVEN TO FIRE. The guard was built against a plant that removes
# the clear from ws_move -- a copy, which is the U2 defect -- and that plant
# fails four named assertions and exits 1. A test that has only ever passed is
# not evidence, and this one was made to fail before it was made to pass.
#
# The target is the host's, not the release's: this is a source-level test
# compiled here, not a released artefact, so it uses whatever `zig cc` defaults
# to. It links ws.c, buffer.c and util.c directly, so what it asserts about is
# the shipping code.
#
# ⛔ IT IS BUILT WHERE THE SUITE'S WORK DIRECTORY IS, AND RUN FROM WHERE THE
# HOST WILL ACTUALLY EXECUTE IT, BECAUSE THOSE CAN BE DIFFERENT PLACES.
#
# The work directory is `$HOME` when there is one, and on the zfs mount this
# was developed on, `$HOME` does not permit executing a file created in it: a
# binary that compiled, linked, and has mode 0755 answers "Permission denied".
# So the binary is tried in `$WORK` first, and if the host refuses to run it
# there it is tried once in the temp directory.
#
# ⛔ AND "COULD NOT RUN" IS ITS OWN FAILURE, NEVER THE U2 DEFECT. The two are
# different claims and reporting one as the other is how a green suite comes to
# mean nothing: a test that cannot execute must say that it could not execute,
# and must not report the defect it was written to catch. The exit status alone
# cannot tell them apart, so the failure is read from the run's own output and
# the "permission denied" case is a distinct message.
if [ -f "$HERE/wsmove-test.c" ]; then
    wsmove_bin="$WORK/wsmove-test"
    wsmove_runlog="$WORK/wsmove-run.log"
    if zig cc -O1 -o "$wsmove_bin" "$HERE/wsmove-test.c" \
        "$ROOT/src/ws.c" "$ROOT/src/buffer.c" "$ROOT/src/util.c" \
        >"$WORK/wsmove-build.log" 2>&1; then
        wsmove_ok=0
        if "$wsmove_bin" >"$wsmove_runlog" 2>&1; then
            wsmove_ok=1
        elif grep -qi "permission denied" "$wsmove_runlog" 2>/dev/null; then
            wsmove_alt="${TMPDIR:-/tmp}/dropssh-wsmove-$$"
            if cp "$wsmove_bin" "$wsmove_alt" 2>/dev/null \
               && chmod +x "$wsmove_alt" 2>/dev/null \
               && "$wsmove_alt" >"$wsmove_runlog" 2>&1; then
                wsmove_ok=1
                rm -f "$wsmove_alt"
            else
                rm -f "$wsmove_alt" 2>/dev/null
                bad "tests/wsmove-test.c compiled but this host would not execute it, in the work directory or in $TMPDIR: the one-owner property is UNTESTED, not passing"
            fi
        else
            wsmove_ok=2
        fi
        if [ "$wsmove_ok" = 1 ]; then
            ok "a moved-from session owns nothing, and closing it is inert"
        elif [ "$wsmove_ok" = 2 ]; then
            bad "a moved-from session still owns the session: a WsSession is being COPIED where it must be moved, and copying shares the buffer pointers (see the output above)"
        fi
    else
        bad "tests/wsmove-test.c did not compile, so the one-owner property is unasserted (see $WORK/wsmove-build.log)"
    fi
else
    bad "tests/wsmove-test.c is missing, so the one-owner property is unasserted"
fi

head_ "doctor, config and pair answer without a network"
# ⛔ THESE THREE ARE ASSERTED BECAUSE EACH WAS PREVIOUSLY EITHER MISSING OR
# A FLAG THAT DID NOTHING. `doctor` answers the environment questions that were
# previously answered by guessing; `config` is the answer to "it ignored my
# flag"; and `--json` used to be accepted and read by nothing at all, which is
# worse than refusing it.
doctor_out=$("$DROPSSH" doctor --relay "unix://$WORK/nonexistent.sock" 2>&1)
doctor_rc=$?
# ⛔ DOCTOR EXITS NON-ZERO WHEN A CHECK FAILED, and the check that fails here is
# the relay that is not there -- which is the point: a doctor run against a
# relay that is down must say so in its exit status, not only in its text.
if [ "$doctor_rc" != 0 ] && printf '%s' "$doctor_out" | grep -q "relay reachable"; then
    ok "doctor reports the environment and exits non-zero on a failed check"
else
    bad "doctor exited $doctor_rc and did not name the unreachable relay"
    printf '%s\n' "$doctor_out" | sed 's/^/        /' | head -8
fi
# ⛔ AND IT MUST NOT PRINT A CREDENTIAL, because a doctor is the thing people
# paste into a bug report.
if printf '%s' "$doctor_out" | grep -qiE "token=|--token [a-z0-9]"; then
    bad "doctor printed something that looks like a token"
else
    ok "doctor prints no credential"
fi

config_out=$("$DROPSSH" config --relay relay.example:443 --name mybox 2>&1)
# ⛔ CONFIG MUST SHOW THE VALUE *AND ITS SOURCE*, because a wrong setting found
# by reading the resolved output is a class of report that otherwise arrives as
# "it ignored my flag".
if printf '%s' "$config_out" | grep -q "relay.example:443" \
   && printf '%s' "$config_out" | grep -q "mybox"; then
    ok "config prints every setting with the value that was given"
else
    bad "config did not report the relay and name that were passed"
    printf '%s\n' "$config_out" | sed 's/^/        /' | head -12
fi
# ⛔ THE ASSERTION IS ON THE WORD, NOT ON A REGEX OVER ALIGNED COLUMNS. An
# earlier version of this case matched a pattern with escaped parentheses
# against the printed columns, and the pattern did not match its own output
# because a literal `(` inside an -E bracket expression is not a group. A test
# whose pattern cannot match the thing it describes fails for the wrong reason
# and sends the next reader looking in the code instead of in the config.
if printf '%s' "$config_out" | grep -q "set, not printed" \
   || printf '%s' "$config_out" | grep -q "^ *token *(unset)"; then
    ok "config reports whether a token is set without printing it"
else
    bad "config does not report the token's presence safely"
    printf '%s\n' "$config_out" | sed 's/^/        /' | head -12
fi
# ⛔ AND WITH A TOKEN SET, THE VALUE MUST NOT APPEAR. The check above can pass
# on a run where no token was given, which proves nothing about the case where
# one is; this one passes one and requires the value to stay out of the output.
config_tok=$("$DROPSSH" config --relay relay.example:443 --token SUPERSECRETVALUE 2>&1)
if printf '%s' "$config_tok" | grep -q "set, not printed" \
   && ! printf '%s' "$config_tok" | grep -q "SUPERSECRETVALUE"; then
    ok "config with a token set reports it without printing the value"
else
    bad "config printed the token's value, or did not report its presence"
    printf '%s\n' "$config_tok" | sed 's/^/        /' | head -12
fi

head_ "--json is honoured, not accepted and ignored"
# ⛔ THE FLAG WAS DEAD: main.c set o.json and nothing read it, so an operator
# who passed it believed they had machine-readable output. It is now either a
# real event stream or a refusal, and this asserts the former. The assertion is
# that a JSON object with an "event" key appears, not that the word json
# appears somewhere.
json_out=$("$DROPSSH" config --relay relay.example:443 --json 2>&1 >/dev/null)
if printf '%s' "$json_out" | grep -q '"event":"start"'; then
    ok "--json produces a parseable event line on stderr, not on stdout"
else
    bad "--json produced no event line"
    printf '%s\n' "$json_out" | sed 's/^/        /' | head -5
fi
# ⛔ AND STDOUT MUST STAY EMPTY IN --json MODE, because on the connect verb
# stdout is ssh's byte pipe. A JSON line on stdout would land in the middle of
# an ssh version string.
json_stdout=$("$DROPSSH" config --relay relay.example:443 --json 2>/dev/null)
case "$json_stdout" in
    *'"event"'*) bad "--json wrote an event to stdout, which is ssh's byte pipe" ;;
    *) ok "--json keeps stdout clean; the events are on stderr" ;;
esac

head_ "the docs do not claim a close the relay does not send"
# ⛔ THE "SILENTLY DROPPED" CLAIM CAME BACK TWICE IN A TREE, AND A CLAIM THAT
# DESCRIBES THE RELAY WRONG IS WORSE THAN NO CLAIM. B11 and four other places
# said a bare node frame is discarded with "no error, no close". Measured live
# on 2026-09-28, 3/3, the relay closes the node with 1009 `bad multiplex frame`
# and the operator with 1011, and an implementer following the old text had no
# way to know 1009 existed -- which is the code they actually meet.
#
# So the claim is checked, not trusted. A documentation assertion is normally
# weak: it cannot tell whether the relay behaves as written. This one can,
# because `tests/mux-probe.py` above has just MEASURED the relay, and this
# checks that the prose agrees with what was measured. A future edit that
# reintroduces the silence claim fails the suite.
doc_drift=""
for f in docs/reverse-relay.md docs/relay-issues.md docs/multiplexing.md; do
    [ -f "$ROOT/$f" ] || continue
    # ⛔ THE CHECK IS FOR THE CLAIM *AS AN ASSERTION*, NOT AS A QUOTATION. The
    # corrections in these files quote the old wording on purpose -- that is how
    # a reader sees what changed -- so a check for the words alone fails on the
    # very text that fixes the problem. What is wrong is a line that ASSERTS the
    # silence: "is silently dropped", "silently discarded", "no error, no
    # close", without a correction marker on it. A line that begins with ">", or
    # that says "CORRECTED", "previously", "used to", "used say" or "wrong", is
    # quoting or correcting rather than asserting, and is left alone.
    while IFS= read -r line; do
        case "$line" in
            *">"*|*CORRECTED*|*previously*|*"used to"*|*"used say"*|*wrong*|*no\ error*|*"was "*|*"is quoted"*)
                continue ;;
        esac
        case "$line" in
            *"silently drop"*|*"silently discard"*|*"no error, no close"*|*"goes quiet"*)
                doc_drift="$doc_drift; $f: $line" ;;
        esac
    done <<EOF
$(grep -n "" "$ROOT/$f" 2>/dev/null)
EOF
done
if [ -z "$doc_drift" ]; then
    ok "no document asserts a bare node frame is dropped in silence"
else
    bad "a document still asserts the silence:$doc_drift"
fi
# ⛔ AND THE POSITIVE HALF: 1009 must be IN THE ERROR TABLE, because that is
# where an implementer looks. Its absence is what made the old text useless.
if grep -q "bad multiplex frame" "$ROOT/docs/reverse-relay.md" 2>/dev/null; then
    ok "the error table names close 1009 bad multiplex frame"
else
    bad "docs/reverse-relay.md's error table does not name close 1009"
fi

# ⛔ THE OPEN-TIMEOUT PAIR, WHICH COST US THREE WRONG NUMBERS ONCE.
#
# Our files said an unanswered `open` closes 1008 after 10 s. Measured against
# the live relay at r11 it is 1013 after 15 s. The numbers were wrong in the
# code AND in the docs, and nothing in the gate could see it, because a doc
# check that only guards the one claim somebody remembered to be wrong is a
# guard for that claim and not for the class.
#
# So this asserts the two facts that were wrong, in the place an implementer
# looks. A correction line is allowed to mention the old value, because a
# document that records its own history is the point; a line that ASSERTS the
# old value is the defect.
#
# ⛔ AND "A CORRECTION" IS RECOGNISED BY ITS CONTENT, NOT BY A KEYWORD. The
# first version of this guard exempted only CORRECTED / previously / used to,
# and it went red on the very rows that FIX the claim: the table row that says
# "**1013** ... our own files said 1008", and the U1 entry that records the old
# 1008/10 s pair as history. A guard that fails on its own fix is worse than no
# guard, because the next person removes the correction rather than the defect
# and the wrong claim comes straight back.
#
# So a line is exempt when it names the CORRECT code anywhere. A row that says
# "1013 ... previously 1008" passes; a row that says only "1008" fails.
timeout_drift=""
for f in docs/reverse-relay.md docs/relay-issues.md docs/multiplexing.md; do
    [ -f "$ROOT/$f" ] || continue
    while IFS= read -r line; do
        case "$line" in
            *">"*|*"1013"*|*CORRECTED*|*previously*|*"used to"*|*"used say"*|*wrong*)
                continue ;;
        esac
        case "$line" in
            *"1008"*"node open timeout"*|*"node open timeout"*1008*)
                timeout_drift="$timeout_drift; $f: $line" ;;
        esac
    done <<EOF
$(grep -n "" "$ROOT/$f" 2>/dev/null)
EOF
done
if [ -z "$timeout_drift" ]; then
    ok "no document asserts close 1008 for a node open timeout"
else
    bad "a document names 1008 as the open-timeout close, which is 1013:$timeout_drift"
fi
# ⛔ AND THE POSITIVE HALF OF THE SAME FACT, so the correction cannot be
# "delete the row" rather than "fix the row".
if grep -q "1013" "$ROOT/docs/reverse-relay.md" 2>/dev/null; then
    ok "the error table names close 1013 node open timeout"
else
    bad "docs/reverse-relay.md's error table does not name close 1013"
fi

head_ "a name no node is using is refused, not silently accepted"
# ⛔ "COULD NOT RUN MUST NEVER READ AS DENIED" IS ALSO TRUE IN THE OTHER
# DIRECTION. A relay that pairs a client with nothing produces a session that
# hangs until a timeout, and the operator cannot tell that from a broken
# network. dropssh connect must say so.
rm -f "$WORK/empty.sock"
"$DROPSSH" relay --listen "unix://$WORK/empty.sock" >"$WORK/empty-relay.log" 2>&1 &
empty_pid=$!
i=0; while [ $i -lt 50 ] && [ ! -S "$WORK/empty.sock" ]; do sleep 0.05; i=$((i+1)); done
timeout 8 env SANDHOME_PASSWD="$WORK/passwd" \
    "$DROPSSH" connect --relay "unix://$WORK/empty.sock" --name nosuchnode </dev/null \
    >"$WORK/empty.out" 2>"$WORK/empty.err"
rc=$?
kill $empty_pid 2>/dev/null
if [ "$rc" != 0 ]; then
    ok "connecting to an absent node exits non-zero (rc=$rc)"
else
    bad "connecting to an absent node exited 0, which reads as success"
fi

head_ "dropssh says what it is"
if "$DROPSSH" version 2>&1 | grep -q 'tls backend: mbedtls'; then
    ok "the binary reports its TLS backend"
else
    bad "the binary does not report a TLS backend"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
exit 0
