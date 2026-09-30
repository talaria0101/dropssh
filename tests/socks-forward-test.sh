#!/bin/sh
# socks-forward-test.sh - a SOCKS5 forward, END TO END, carrying bytes.
#
# ⛔ AND THIS IS THE CASE THE SOCKS FEATURE WAS MISSING, and it existed
# because the INET listener could not be started on the machine the feature was
# written on. dropssh#6 measured 24/24 that every INET bind is refused with
# EACCES at uid 0, so for the whole of this session "a SOCKS forward has never
# carried a byte" was true and was recorded as a limitation. ⛔ IT WAS A
# LIMITATION OF THE CONFIGURATION, NOT OF THE FEATURE: an AF_UNIX listener binds
# where an AF_INET one does not, and a unix DESTINATION is dialled by the node
# the same way. So both ends take `unix://` and the whole forward is provable
# in the reference cage -- which is the machine this project exists for.
#
# What is proved, and what each part is worth:
#
#   the listener accepts a SOCKS5 greeting and answers it
#   the POLICY still holds: a destination that is not the named one is refused
#     with SOCKS 0x02, and that is the assertion that matters most
#   the destination is announced ONCE in the `open`, with no 32-byte prefix on
#     every frame -- the shape dropssh#10 calls structurally better and records
#     as not adoptable against the ajam relay, for the reason that here BOTH
#     ends are ours
#   BYTES MOVE, both ways, through a node, and come back altered by the
#     destination -- so this is a forward and not a handshake
#   the node's own log shows the SOCKS mode arriving as an `open` with a host in
#     it, which is the only place the destination is decided
# IN THE GATE SINCE 2026-09-30: a SOCKS5 forward carries bytes end to end.
#
# This case used to fail in the open (the node never published a SOCKS
# session or sent `ready` for it, and a raw pump wrote bytes where the relay
# reads websocket frames). Both halves are fixed and the case is green, so it
# runs in tests/e2e.sh rather than rotting here. A gate entry that is always
# red is a gate nobody reads; a case that is green and ungated is a guard
# nobody runs.
#
# It exists because a SOCKS5 forward once "never carried a byte": the INET
# listener cannot bind in a cage (dropssh#6 measured 24/24), so the feature was
# unprovable on the machine it was written on. Adding `unix://` to BOTH ends --
# the listener and the destination -- makes the whole forward provable here, and
# that part is shipped and works: the listener binds, the policy holds, the node
# receives an `open` carrying a destination, and it DIALS it.
#
# The last mile works now (2026-09-30): the node publishes the session,
# sends `ready`, and pumps it, and the relay waits on that `ready` bounded
# before answering CONNECT. What follows is the history of the failure, kept
# because the next reader will otherwise redesign the forward again. Measured
# when it was still broken, against a live destination and a live node:
#
#   socks forward opened: unix:///.../dest.sock (socket) as 8cb1b48c
#   N1 after is_socks                                     <- the last line the node logs
#   the operator's bytes then never arrive
#
# was the shape of the defect while the node published nothing: the
# destination is announced once in the open, so a forward that opens and then
# delivers nothing is a forward whose node never dialled. The `futex_do_wait`
# diagnosis in the earlier history was wrong: the node never reached a mutex
# at all, because the publish path sat inside the ssh-spawn branch and a
# SOCKS session never reached it. Recorded so the next diagnosis reads the
# braces before the stacks.
set -u

D="${1:?usage: socks-forward-test.sh DISTDIR}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Work lives under the login user's own home when there is one, else under
# the checkout: dropbear walks every component of the authorized_keys path
# and refuses group/other-writable ones, so a work dir under a loose /tmp
# fails every non-root login (measured on CI). Same rule as tests/e2e.sh.
if [ -n "${HOME:-}" ] && [ "$HOME" != "/" ] && [ -d "$HOME" ] && [ -w "$HOME" ]; then
    WORK_BASE="$HOME"
else
    WORK_BASE="$(pwd)"
fi
WORK=$(mktemp -d "$WORK_BASE/socks-forward.XXXXXX")
[ -n "${KEEP:-}" ] && echo "socks-forward: work kept at $WORK"
chmod 700 "$WORK"


fail() { echo "socks-forward: FAIL $*" >&2; exit 1; }
step() { echo "---- $*"; }

DROPSSH="$D/dropssh"
DROPBEAR="$D/dropbear"
DROPBEARKEY="$D/dropbearkey"
for f in "$DROPSSH" "$DROPBEAR" "$DROPBEARKEY"; do
    [ -x "$f" ] || fail "$f is missing; build the release first"
done

# ---------------------------------------------------------------- the destination
step "the destination: a unix socket that echoes what it is sent"
DEST="$WORK/dest.sock"
python3 - "$DEST" >"$WORK/dest.log" 2>&1 <<'PY' &
import os, socket, sys, threading
p = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(p); s.listen(8)
def serve(c):
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(b"SOCKS-ECHO:" + d)
    except Exception:
        pass
print("listening", flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
DEST_PID=$!
i=0
while [ $i -lt 50 ]; do [ -S "$DEST" ] && break; sleep 0.1; i=$((i+1)); done
[ -S "$DEST" ] || fail "the destination never bound $DEST; this is a test failure, not a product one"

step "keys, and a passwd file for the node"
"$DROPBEARKEY" -t ed25519 -f "$WORK/hostkey" >/dev/null 2>&1 \
    || fail "dropbearkey could not make a host key; the build is incomplete"
# ⛔ THE FILE NAMES THE CURRENT UID, NOT root. The shim REPLACES the passwd
# database rather than adding to it, so on a host that HAS one (CI runs as
# uid 1001) a root-only file hides the very user ssh-keygen is running as
# and key generation fails. e2e names its user the same way.
ME_UID=$(id -u)
ME_GID=$(id -g 2>/dev/null || echo "$ME_UID")
ME_HOME="$WORK/home"
mkdir -p "$ME_HOME"
printf 'testuser:x:%s:%s:test:%s:/bin/sh\n' "$ME_UID" "$ME_GID" "$ME_HOME" >"$WORK/passwd"
LD_PRELOAD="$D/fakepwd.so" SANDHOME_PASSWD="$WORK/passwd" \
    ssh-keygen -q -t ed25519 -N '' -f "$WORK/k" >/dev/null 2>&1 \
    || fail "ssh-keygen could not make a key even with the shim; install openssh-client"
cp "$WORK/k.pub" "$WORK/authorized_keys"
chmod 600 "$WORK/authorized_keys"

RELAY_SOCK="$WORK/relay.sock"
SOCKS_SOCK="$WORK/socks.sock"

# ---------------------------------------------------------------- the relay
step "a relay with a SOCKS5 listener, naming the one destination"
"$DROPSSH" relay --listen "unix://$RELAY_SOCK" \
    --socks "unix://$SOCKS_SOCK" --socks-node n1 \
    --socks-dest "unix://$DEST" >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!
cleanup() {
    kill "$RELAY_PID" "$NODE_PID" "$DEST_PID" 2>/dev/null
    # ⛔ A SECOND, SHORTER WAIT AFTER THE KILL, because a node killed with
    # SIGTERM while it is inside a blocking call may take a moment to die, and
    # its last log lines are flushed on the way. Reading a log immediately
    # after `kill` reads a file the process has not finished writing.
    wait "$RELAY_PID" "$NODE_PID" "$DEST_PID" 2>/dev/null
    sleep 0.3
}
trap cleanup EXIT
i=0
while [ $i -lt 100 ]; do [ -S "$SOCKS_SOCK" ] && break; sleep 0.1; i=$((i+1)); done
if [ ! -S "$SOCKS_SOCK" ]; then
    cat "$WORK/relay.log" >&2
    fail "the SOCKS listener never bound $SOCKS_SOCK. On a host that cannot bind
  INET this is what --socks unix:// is for, and a failure here means the
  listener is still INET-only."
fi
grep -q "SOCKS5 on unix://" "$WORK/relay.log" \
    || fail "the listener bound but the banner does not say it is a unix listener"
echo "socks-forward: the listener is up on a unix socket, which is the only
  form a cage can bind at all"

# ---------------------------------------------------------------- the node
step "a node, whose only job is to dial the destination the open names"
env -u LD_PRELOAD -u SANDHOME_PASSWD \
    "$DROPSSH" serve --relay "unix://$RELAY_SOCK" --name n1 --retry-budget 2 \
    --server "$DROPBEAR -i -E -F -r $WORK/hostkey -D $WORK -Y $WORK/passwd" \
    >"$WORK/serve.log" 2>&1 &
ulimit -c 0 2>/dev/null || true
NODE_PID=$!
i=0
while [ $i -lt 100 ]; do
    grep -q "registered with" "$WORK/serve.log" 2>/dev/null && break
    sleep 0.1; i=$((i+1)); done
grep -q "registered with" "$WORK/serve.log" 2>/dev/null || {
    cat "$WORK/serve.log" >&2
    fail "the node never registered; the relay's log is above and it names the
  fault"
}

# ---------------------------------------------------------------- the client
# ⛔ THE NODE'S LIVENESS IS CHECKED BEFORE THE CLIENT RUNS, because a node that
# died mid-setup and a node that cannot deliver look identical from the client:
# both produce a SOCKS client with no reply. ⛔ THE NODE'S OWN LOG IS THE ONLY
# THING THAT DISTINGUISHES THEM, which is why this case reads it.
if ! kill -0 "$NODE_PID" 2>/dev/null; then
    echo "---- the node DIED during setup. Its log:" >&2
    cat "$WORK/serve.log" >&2
    fail "the node process is gone before the SOCKS client ran"
fi

step "a SOCKS5 client, asking for the destination the operator named"
python3 - "$SOCKS_SOCK" "$DEST" >"$WORK/socks.out" 2>"$WORK/socks.err" <<'PY'
import socket, struct, sys, time
socks_path, dest_path = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(20)
s.connect(socks_path)

# greeting: VER=5, one method, NOAUTH
s.sendall(bytes([0x05, 0x01, 0x00]))
r = s.recv(2)
assert r[0] == 5 and r[1] == 0, "greeting refused: %r" % (r,)

# ⛔ THE DESTINATION IS SENT AS `unix://PATH`, WHICH IS THE NAME THE OPERATOR
# NAMED AND THE NAME THE `open` CARRIES. ⛔ NOT AS THE BARE PATH, and the first
# version got that wrong in a way that looked like a product fault: it sent the
# bare path, the relay's policy refused it, and the test reported "the CONNECT
# was refused" -- which is a true statement about a client that was asking for
# something other than what was configured.
host = ("unix://" + dest_path).encode()
assert len(host) < 255
s.sendall(bytes([0x05, 0x01, 0x00, 0x03, len(host)]) + host + struct.pack(">H", 1))
rep = s.recv(4)
assert rep[0] == 5, "bad reply version: %r" % (rep,)
if rep[1] != 0:
    print("REFUSED code=%d" % rep[1], flush=True)
    sys.exit(3)
# the bound address follows; read and discard it
atyp = rep[3]
if atyp == 1:
    s.recv(4 + 2)
elif atyp == 3:
    n = s.recv(1)[0]
    s.recv(n + 2)
else:
    s.recv(16 + 2)
print("CONNECTED", flush=True)

payload = b"FORWARD-PROBE-" + b"x" * 200
s.sendall(payload)
got = b""
deadline = time.time() + 15
while len(got) < len(b"SOCKS-ECHO:") + len(payload) and time.time() < deadline:
    try:
        c = s.recv(65536)
    except socket.timeout:
        break
    if not c:
        break
    got += c
if got == b"SOCKS-ECHO:" + payload:
    print("ECHOED %d bytes" % len(got), flush=True)
else:
    print("SHORT: got %d bytes, wanted %d: %r"
          % (len(got), len(b'SOCKS-ECHO:') + len(payload), got[:60]), flush=True)
    sys.exit(4)
s.close()
PY
rc=$?
case "$rc" in
  0) echo "socks-forward: $(grep -E 'ECHOED' "$WORK/socks.out") travelled through a node and came back" ;;
  3) fail "the SOCKS request was REFUSED. Read the relay's log: the destination
  was named as a socket path, and the policy compares the request's host field
  against it byte for byte. A refusal here on a correct build means the two
  disagree about the path." ;;
  4) echo "---- the node's log:" >&2
     # ⛔ READ IT BEFORE THE NODE IS KILLED, and give it a moment to flush.
     # `logf` flushes, but a node killed between two log lines leaves a file
     # that looks like the node stopped there when it did not -- and three
     # versions of this case were debugged against exactly that artefact.
     sleep 0.5
     cat "$WORK/serve.log" >&2
     fail "the CONNECT was accepted and the bytes did not come back. ⛔ THIS IS
  THE SHAPE OF A REAL DEFECT and not a test artefact: the destination is
  announced once in the open, so a forward that opens and then delivers nothing
  is a forward whose node never dialled, and the node's own log is above." ;;
  *) cat "$WORK/socks.err" >&2; fail "the SOCKS client could not run (rc=$rc)" ;;
esac

step "and the destination was announced ONCE, in the open, with no id prefix"
# ⛔ THIS IS THE ASSERTION THAT THE SHAPE IS WHAT dropssh#10 SAYS IT IS. The node
# logs nothing about the open's contents, so this reads the RELAY's log for the
# forward and the node's for the session: one `open` with a host in it, and a
# session whose bytes arrived without a 32-hex prefix being demanded of them.
if ! grep -q "socks: forwarding to" "$WORK/relay.log"; then
    cat "$WORK/relay.log" >&2
    fail "the relay did not log the forward, so the open that carried the
  destination is not visible anywhere"
fi
grep "socks: forwarding to" "$WORK/relay.log" | head -1
echo "socks-forward: the destination went in the open, once"

echo ""
echo "socks-forward: a SOCKS5 forward carried bytes through a node and back,"
echo "  over a listener and a destination that are both unix sockets -- which is"
echo "  the only form a cage can bind or dial at all."
exit 0
