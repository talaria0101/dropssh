#!/bin/sh
# static-server-test.sh - a STATIC(-pie) musl dropbear serves a real login.
#
# R9 removed the shim requirement (-Y FILE reads the passwd database with no
# LD_PRELOAD), which removes the only reason the server had to be dynamic
# glibc. This case proves a static musl server authenticates with NO shim in
# its environment. The CLIENT still gets the shim: ssh(1) on a host with no
# /etc/passwd cannot map its own uid, which is a fact about the sandbox and
# not about the server under test.
# USAGE: static-server-test.sh DISTDIR STATIC_DROPBEAR
set -u
D="${1:?usage: static-server-test.sh DISTDIR STATIC_DROPBEAR}"
SDB="${2:?usage: static-server-test.sh DISTDIR STATIC_DROPBEAR}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/static-server.XXXXXX")
chmod 700 "$WORK"
fail() { echo "static-server: FAIL $*" >&2; exit 1; }
DROPSSH="$D/dropssh"
SHIM="$D/fakepwd.so"
[ -x "$DROPSSH" ] || fail "$DROPSSH missing"
[ -x "$SDB" ] || fail "$SDB missing; build the static server first"
file -b "$SDB" | grep -qE 'statically linked|static-pie linked' \
    || fail "$SDB is not static: $(file -b "$SDB")"
echo "static-server: subject is $(file -b "$SDB" | cut -c1-60)"
"$D/dropbearkey" -t ed25519 -f "$WORK/hostkey" >/dev/null 2>&1 \
    || fail "dropbearkey failed"
ME_UID=$(id -u)
# ⛔ THE LOGIN IS WHOEVER RUNS THE TEST, NOT root. dropbear refuses a login
# whose uid differs from the server's, so the passwd entry carries the
# current uid under a fixed name (there is no /etc/passwd to ask for one).
ME_HOME="$WORK/home"
mkdir -p "$ME_HOME"
# The home must be owned by the login user: dropbear refuses a login whose
# home is owned by someone else and writable. /tmp fails that for non-root.
printf 'testuser:x:%s:%s:test:%s:/bin/sh\n' "$ME_UID" "$ME_UID" "$ME_HOME" >"$WORK/passwd"
LD_PRELOAD="$SHIM" SANDHOME_PASSWD="$WORK/passwd" \
    ssh-keygen -q -t ed25519 -N '' -f "$WORK/k" >/dev/null 2>&1 \
    || fail "ssh-keygen failed"
mkdir -p "$WORK/ak" && cp "$WORK/k.pub" "$WORK/ak/authorized_keys"
chmod 600 "$WORK/ak/authorized_keys"
SOCK="$WORK/relay.sock"
"$DROPSSH" relay --listen "unix://$SOCK" >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!
i=0; while [ $i -lt 50 ] && [ ! -S "$SOCK" ]; do sleep 0.05; i=$((i+1)); done
[ -S "$SOCK" ] || { cat "$WORK/relay.log" >&2; fail "relay never bound"; }
# ⛔ NO shim in the server's environment: absent, not unset.
env -u LD_PRELOAD -u SANDHOME_PASSWD \
    "$DROPSSH" serve --relay "unix://$SOCK" --name st1 --retry-budget 2 \
    --server "$SDB -i -E -F -r $WORK/hostkey -D $WORK/ak -Y $WORK/passwd" \
    >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
sleep 0.8
kill -0 "$SERVE_PID" 2>/dev/null || { cat "$WORK/serve.log" >&2; fail "node died at startup"; }
LD_PRELOAD="$SHIM" SANDHOME_PASSWD="$WORK/passwd" \
timeout 40 ssh \
    -o "ProxyCommand=$DROPSSH connect --relay unix://$SOCK --name st1" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR \
    -i "$WORK/k" testuser@st1 'echo STATIC_PROVEN; id -u' \
    >"$WORK/out" 2>"$WORK/err"
rc=$?
kill $SERVE_PID $RELAY_PID 2>/dev/null
wait 2>/dev/null
if [ $rc -ne 0 ]; then cat "$WORK/err" >&2; cat "$WORK/serve.log" >&2; fail "ssh exited $rc"; fi
grep -q STATIC_PROVEN "$WORK/out" || { cat "$WORK/out" "$WORK/err" >&2; fail "no marker"; }
grep -qx "$ME_UID" "$WORK/out" || { cat "$WORK/out" >&2; fail "uid wrong"; }
echo "static-server: a static-pie musl dropbear served a real login with no shim"
exit 0
