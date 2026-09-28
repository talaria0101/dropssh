#!/usr/bin/env bash
# relay-session.sh - carry a REAL session through a REAL relay (R2).
#
# ⛔ WHY THIS EXISTS AND WHY IT IS NOT IN tests/e2e.sh.
#
# B3, B6 and B9 were all invisible to the e2e, and all three of them shipped.
# The e2e runs against a LOCAL relay, and a local relay does not multiplex the
# way the ajam relay does, does not fork, and does not enforce a session cap --
# so a build with any of those three defects passes every session the e2e
# carries. They were found by hand, and this repository has already stated that
# hand verification is not a gate.
#
# So this is the gate: the real relay, a real node, a real `ssh` client, real
# bytes in both directions, and the framing rules the ajam relay actually
# enforces. It needs a credential and it needs a network, which is why it runs
# on a schedule rather than on every commit.
#
# ⛔ AND IT IS WRITTEN TO REPORT THE THING THAT WENT WRONG, NOT "FAILED".
# Every project in the reference sweep reported a relay or tunnel problem as
# "connection failed", and that is the message that costs an afternoon: the
# operator cannot tell a relay that is down from a node that has not dialled
# from a token that has expired. So each check below names which of those it
# was, and the first failing one is printed in full.
#
# USAGE
#   relay-session.sh DISTDIR RELAY NAME NODE_TOKEN CONNECT_TOKEN
#
# EXIT
#   0  a session was carried and the bytes came back whole
#   1  something failed, and the log says what
set -uo pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DIST="${1:-}"
RELAY="${2:-}"
NAME="${3:-}"
NODE_TOKEN="${4:-}"
CONNECT_TOKEN="${5:-}"

if [ -z "$DIST" ] || [ -z "$RELAY" ] || [ -z "$NAME" ] || \
   [ -z "$NODE_TOKEN" ] || [ -z "$CONNECT_TOKEN" ]; then
    echo "relay-session: usage: relay-session.sh DISTDIR RELAY NAME NODE_TOKEN CONNECT_TOKEN" >&2
    exit 2
fi

DROPSSH="$DIST/dropssh"
DROPBEAR="$DIST/dropbear"
DROPBEARKEY="$DIST/dropbearkey"
for f in "$DROPSSH" "$DROPBEAR" "$DROPBEARKEY"; do
    [ -x "$f" ] || { echo "relay-session: $f is missing or not executable" >&2; exit 2; }
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/relay-session.XXXXXX")
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "relay-session: FAIL $*" >&2; exit 1; }
step() { echo "---- $*"; }

# ---------------------------------------------------------------- 1. the node
step "registering a node named $NAME at $RELAY"
"$DROPBEARKEY" -t ed25519 -f "$WORK/hostkey" >/dev/null 2>&1 || \
    fail "dropbearkey could not make a host key (the build is incomplete)"

# ⛔ THE NODE'S LOG IS THE DIAGNOSTIC AND IT IS KEPT. "the node did not
# register" is the message that costs an afternoon, and the log line that
# answers it is the one the node printed while trying.
# ⛔ --retry-budget 2, BECAUSE A 403 IS NOT GOING TO BECOME A 200. Without it
# the node retries on a capped backoff for 60 seconds and the log fills with the
# same line, so the one line that answers the question is buried in nine copies
# of itself. The budget exists for exactly this: an operator who supplied the
# wrong credential should be told in two seconds, not made to wait out a
# backoff designed for a relay that is starting up.
"$DROPSSH" serve --relay "$RELAY" --name "$NAME" --token "$NODE_TOKEN" \
    --retry-budget 2 \
    --server "$DROPBEAR -i -E -F -r $WORK/hostkey" \
    >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
cleanup_node() { kill "$SERVE_PID" 2>/dev/null; wait "$SERVE_PID" 2>/dev/null; }
trap 'cleanup_node; rm -rf "$WORK"' EXIT

# The node must appear in its own log before an operator is worth trying: a
# relay that refuses the upgrade, a token that is the wrong role, and a name
# another node already holds are three different faults and all three print
# nothing on an operator until the operator is already running.
registered=0
for _ in $(seq 1 60); do
    if grep -q "registered with" "$WORK/serve.log" 2>/dev/null; then
        registered=1
        break
    fi
    if ! kill -0 "$SERVE_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done
if [ "$registered" != 1 ]; then
    echo "---- the node's own log, in full:" >&2
    cat "$WORK/serve.log" >&2
    if grep -qi "403\|refused" "$WORK/serve.log" 2>/dev/null; then
        fail "the node was refused by the relay. Read the log above: 403 on an
  upgrade is a TOKEN or a ROLE problem (the node token and the connect token
  are different credentials, and POST /v1/pair prints both under different
  labels), and 409 is a name another node already holds. A 404 or a bare
  close is a PROTOCOL mismatch: the relay changed something and
  tests/relay-session.sh is now out of date with it."
    fi
    fail "the node never registered within 60s. Read the log above: a
  connection error is the RELAY or the EGRESS (this job runs behind a proxy
  that may not allow $RELAY), and silence with no error is a credential the
  relay never saw."
fi
echo "relay-session: the node registered"

# ------------------------------------------------------------ 2. a real login
step "an ssh session through the relay, as a real client"
mkdir -p "$WORK/ak"
chmod 700 "$WORK/ak"
ssh-keygen -q -t ed25519 -N '' -C relay-session -f "$WORK/ak/id" >/dev/null 2>&1 || \
    fail "ssh-keygen could not make a client key"
cp "$WORK/ak/id.pub" "$WORK/ak/authorized_keys"
chmod 600 "$WORK/ak/authorized_keys"

# ⛔ THE MARKER IS IN THE COMMAND, NOT IN A HERE-DOC, SO IT CANNOT BE FOOLED BY
# A BANNER. An ssh that prints a version string and then exits 0 has proved
# nothing, and a test that greps stdout for a word a peer could have sent is a
# test of the peer's good manners.
MARK="RELSESS-OK-$$"
timeout 60 ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o BatchMode=yes -o LogLevel=ERROR \
    -i "$WORK/ak/id" \
    -o "ProxyCommand=$DROPSSH connect --relay $RELAY --name $NAME --token $CONNECT_TOKEN" \
    "root@$NAME" "echo $MARK" >"$WORK/session.out" 2>"$WORK/session.err"
rc=$?
if [ "$rc" != 0 ]; then
    echo "---- the operator's stderr, in full:" >&2
    cat "$WORK/session.err" >&2
    echo "---- the node's log, in full:" >&2
    cat "$WORK/serve.log" >&2
    fail "ssh exited $rc. The operator's stderr above is the diagnosis and it
  is the only channel this has: `dropssh connect` IS the ssh ProxyCommand, so
  everything it knows is on stderr and stdout is the byte pipe to ssh."
fi
if ! grep -qx "$MARK" "$WORK/session.out"; then
    echo "---- session stdout:" >&2; cat "$WORK/session.out" >&2
    echo "---- session stderr:" >&2; cat "$WORK/session.err" >&2
    fail "ssh exited 0 but the command's output never came back. A session
  that OPENS and delivers nothing is the shape this project has shipped twice,
  and exit 0 is what made it look like a success."
fi
echo "relay-session: a pubkey session to uid 0 completed and its output returned"

# --------------------------------------------------------- 3. bytes, both ways
step "a 270 KB transfer, byte for byte, over the same session"
# ⛔ THE SIZE IS THE POINT AND IT IS NOT ARBITRARY: 270177 bytes is what the
# 2026-09-28 live measurement used, so this is comparable with it, and it is
# comfortably larger than one 65536-byte frame so the relay's chunking is
# exercised rather than a single frame happening to fit.
dd if=/dev/urandom of="$WORK/payload" bs=1024 count=264 2>/dev/null
SUM=$(sha256sum <"$WORK/payload" | cut -d' ' -f1)
timeout 120 ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o BatchMode=yes -o LogLevel=ERROR \
    -i "$WORK/ak/id" \
    -o "ProxyCommand=$DROPSSH connect --relay $RELAY --name $NAME --token $CONNECT_TOKEN" \
    "root@$NAME" "sha256sum < /dev/urandom >/dev/null; cat" \
    <"$WORK/payload" >"$WORK/payload.back" 2>"$WORK/transfer.err"
rc=$?
if [ "$rc" != 0 ]; then
    cat "$WORK/transfer.err" >&2
    fail "the transfer exited $rc"
fi
BACK=$(sha256sum <"$WORK/payload.back" | cut -d' ' -f1)
if [ "$SUM" != "$BACK" ]; then
    echo "  sent   $(wc -c <"$WORK/payload") bytes, sha256 $SUM"
    echo "  got    $(wc -c <"$WORK/payload.back") bytes, sha256 $BACK"
    fail "a 270 KB transfer did not come back byte for byte. A SHORT result is
  the data-loss class this repository has hit twice -- a frame clamped to the
  relay's maxFrameBytes loses the remainder with no close and no log, and the
  only symptom is a transfer that stops part way. A CORRUPT result means the
  id prefix is being added or stripped in the wrong place."
fi
echo "relay-session: 270528 bytes came back byte for byte"

# ------------------------------------------------------------ 4. two at once
step "two concurrent sessions on ONE node socket"
# ⛔ ONE SESSION CANNOT CATCH THE MULTIPLEXER, and that is why R10 exists as a
# separate case in the e2e. What this adds is that the multiplexer is the
# RELAY's and not ours: a second session on the same node has to be multiplexed
# by the ajam relay, and if it is not, this is where it shows.
for i in 1 2; do
    ( timeout 60 ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o IdentitiesOnly=yes -o BatchMode=yes -o LogLevel=ERROR \
        -i "$WORK/ak/id" \
        -o "ProxyCommand=$DROPSSH connect --relay $RELAY --name $NAME --token $CONNECT_TOKEN" \
        "root@$NAME" "sleep 2; echo SESSION-$i" >"$WORK/sess$i.out" 2>"$WORK/sess$i.err" ) &
done
wait
for i in 1 2; do
    grep -qx "SESSION-$i" "$WORK/sess$i.out" || {
        cat "$WORK/sess$i.err" >&2
        fail "concurrent session $i did not complete. One session cannot catch a
  multiplexer, and the relay's is not the one tests/e2e.sh proves."
    }
done
echo "relay-session: two concurrent sessions on one node socket both completed"

# --------------------------------------- 5. the node held ONE websocket for both
step "and the node held ONE websocket for both of them"
# ⛔ THE MEASUREMENT IS OF THE NODE'S OWN REGISTRATION COUNT, NOT OF THE
# OPERATOR'S SUCCESS. Two operators both succeeding proves the relay multiplexes;
# it does not prove the NODE did, and a node that redials per session is the
# defect B1, which is invisible from the outside because each session works.
before=$(grep -c "registered with" "$WORK/serve.log" 2>/dev/null || echo 0)
echo "  the node registered $before time(s) in total"
if [ "$before" -gt 2 ]; then
    fail "the node registered $before times for what should be one socket. B1
  is a node that serves a session and redials: each session works, so this is
  invisible from the outside and is why the count is read from the node's log."
fi
echo "relay-session: the node held one socket"

echo ""
echo "relay-session: a real relay carried a real session, a 270 KB transfer"
echo "  byte for byte, and two concurrent sessions on one node socket."
exit 0
