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
