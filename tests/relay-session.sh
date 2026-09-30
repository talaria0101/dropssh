#!/bin/sh
# R2, done properly: a real session through the real relay, on a pair THIS RUN
# minted for itself.
#
# ⛔ AND EVERY CLAIM THIS SCRIPT USED TO MAKE ABOUT A CREDENTIAL WAS WRONG.
# It said a pair is per-pair and per-role and "cannot be obtained from the
# outside", and that R2 needs three repository secrets. Read against the
# relay's own served documentation (llms.txt, version 2026-09-28-r12) that is
# false: `POST /v1/pair` with an empty body is SELF-SERVICE, the agent mints it
# itself, and `expires` is "never later than 72h after creation". So R2 never
# needed a secret at all -- it needed the relay's own documentation, which
# nobody had read this session.
#
# ⛔ WHICH IS THE LESSON, AND IT IS THE SAME ONE AS #8 IN dropssh#10. A claim
# about someone else's service, made from memory and carried in prose, drifts
# from the service. The fix is not to remember harder: it is to FETCH, which is
# what `scripts/fetch-relay-spec.sh` does and what this script now does before
# it believes anything.
set -u

D="${1:?usage: relay-session.sh DISTDIR [RELAY]}"
RELAY="${2:-tcp.ssh.relay.ajam.dev}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/relay-session.XXXXXX")
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "relay-session: FAIL $*" >&2; exit 1; }
step() { echo "---- $*"; }

# ⛔ THE RELAY'S OWN DOCUMENT IS FETCHED FIRST, AND ITS VERSION IS PRINTED,
# BECAUSE EVERY CLAIM BELOW IS A CLAIM ABOUT IT. A measurement of a service
# whose specification may have moved is a measurement of a guess.
step "the relay's version, from its own /health"
ver=$(curl -fsSL --max-time 20 "https://$RELAY/health" 2>/dev/null \
      | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
echo "  version ${ver:-unknown}"
[ -n "$ver" ] || fail "could not read the relay's version; every check below is a claim about a service whose specification is then unknown"

step "minting a pair with POST /v1/pair, empty body, no credential"
pair=$(curl -fsSL --max-time 30 -X POST "https://$RELAY/v1/pair" \
       -H 'content-type: application/json' -d '{}' 2>/dev/null) \
    || fail "POST /v1/pair did not answer. Per the served documentation it is self-service with an empty body; a refusal here means the endpoint changed, and this script is now out of date with it."
echo "$pair" >"$WORK/pair.json"
NAME=$(printf '%s' "$pair" | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
NODE_TOKEN=$(printf '%s' "$pair" | sed -n 's/.*"node_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
CONN_TOKEN=$(printf '%s' "$pair" | sed -n 's/.*"connect_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
[ -n "$NAME" ] && [ -n "$NODE_TOKEN" ] && [ -n "$CONN_TOKEN" ] \
    || fail "the pair answer had no name, or no node_token, or no connect_token: $pair"
echo "  name $NAME"
echo "  expires in $(( ($(printf '%s' "$pair" | sed -n 's/.*"expires"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p') - $(date +%s000)) / 60000 )) minutes"
# ⛔ THE TOKENS ARE NOT PRINTED. This script's own output is a thing people
# paste into a bug report, and the two lines above are a node's entire
# credential. The name is printed because it is in every log line anyway.

DROPSSH="$D/dropssh"
[ -x "$DROPSSH" ] || fail "$DROPSSH is missing; build the release first"
DROPBEAR="$D/dropbear"
DROPBEARKEY="$D/dropbearkey"

step "a host key and a client key"
"$DROPBEARKEY" -t ed25519 -f "$WORK/hostkey" >/dev/null 2>&1 \
    || fail "dropbearkey could not make a host key; the build is incomplete"
# ⛔ THE FILE NAMES THE CURRENT UID AND COMES BEFORE KEYGEN, AND THE LOGIN
# USER IS THE CURRENT USER. The shim REPLACES the passwd database rather
# than adding to it, so on a host that HAS one (CI runs as uid 1001) a
# root-only file hides the very user ssh-keygen runs as. And dropbear
# refuses a login whose uid differs from the server's, so root@ only works
# where the server runs as root.
ME_UID=$(id -u)
ME_GID=$(id -g 2>/dev/null || echo "$ME_UID")
# `id -un` with no passwd database prints the numeric id AND fails, which
# poisons a plain `||` fallback with a two-line name ssh rejects. So uid 0
# is root by rule, and anything else must look like a name to be used.
if [ "$ME_UID" = 0 ]; then
    ME_NAME=root
else
    ME_NAME=$(id -un 2>/dev/null)
    case "$ME_NAME" in
        ''|*[!a-zA-Z0-9._-]*) ME_NAME=testuser ;;
    esac
fi
ME_HOME="$WORK/home"
mkdir -p "$ME_HOME"
# The home must be owned by the login user: dropbear refuses a login whose
# home is owned by someone else and writable ("must be owned by user or
# root"). /tmp fails that check for any non-root login.
printf '%s:x:%s:%s:test:%s:/bin/sh\n' "$ME_NAME" "$ME_UID" "$ME_GID" "$ME_HOME" >"$WORK/passwd"
# ⛔ ssh-keygen NEEDS A PASSWD ENTRY FOR ITS OWN UID, and a cage has none, so
# the CLIENT gets the shim even though the SERVER -- which is the thing under
# test -- does not. On this sandbox "No user exists for uid 0" is OpenSSH
# complaining about the client, and reading it as an R2 failure is how this
# looked broken for twenty minutes on an earlier attempt.
LD_PRELOAD="$D/fakepwd.so" SANDHOME_PASSWD="$WORK/passwd" \
    ssh-keygen -q -t ed25519 -N '' -f "$WORK/user_ed25519" >/dev/null 2>&1 \
    || fail "ssh-keygen could not make a client key; with the shim preloaded this is a real fault"
cp "$WORK/user_ed25519.pub" "$WORK/authorized_keys"
chmod 600 "$WORK/authorized_keys"

step "the node, registering at $RELAY as $NAME"
# ⛔ NO LD_PRELOAD FOR THE SERVER, AND NOT --preload EITHER. The server reads
# its passwd database with -Y, so it is proving the R9 claim at the same time
# as the R2 one.
env -u LD_PRELOAD -u SANDHOME_PASSWD \
    "$DROPSSH" serve --relay "$RELAY" --name "$NAME" --token "$NODE_TOKEN" \
    --retry-budget 2 \
    --server "$DROPBEAR -i -E -F -r $WORK/hostkey -D $WORK -Y $WORK/passwd" \
    >"$WORK/serve.log" 2>&1 &
SERVE_PID=$!
cleanup() { kill "$SERVE_PID" 2>/dev/null; wait "$SERVE_PID" 2>/dev/null; }
trap 'cleanup; rm -rf "$WORK"' EXIT

registered=0
for _ in $(seq 1 60); do
    if grep -q "registered with" "$WORK/serve.log" 2>/dev/null; then
        registered=1; break
    fi
    kill -0 "$SERVE_PID" 2>/dev/null || break
    sleep 1
done
if [ "$registered" != 1 ]; then
    echo "---- the node's own log, in full:" >&2
    cat "$WORK/serve.log" >&2
    if grep -qi "403\|refused" "$WORK/serve.log" 2>/dev/null; then
        fail "the node was refused by the relay. A 403 on an upgrade is a
  TOKEN or a ROLE problem: the node token and the connect token are different
  credentials, and POST /v1/pair prints both under different labels. A 409 is
  a name collision, which the served documentation says to retry with a fresh
  pair -- the names are 128-bit random, so it should not happen. A 503 is
  issuance disabled."
    fi
    fail "the node never registered within 60s, and the log above says why or
  says nothing at all, which is itself the answer: silence with no error is an
  egress that never reached the relay."
fi
echo "relay-session: the node registered at $RELAY, with NO LD_PRELOAD in its
  environment and its passwd database read from a file"

step "a real ssh login through the relay, as a real client"
LD_PRELOAD="$D/fakepwd.so" SANDHOME_PASSWD="$WORK/passwd" \
timeout 60 ssh \
    -o "ProxyCommand=$DROPSSH connect --relay $RELAY --name $NAME --token $CONN_TOKEN" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o ConnectTimeout=20 -o LogLevel=ERROR \
    -i "$WORK/user_ed25519" "$ME_NAME@$NAME" 'echo RELAY-LOGIN-OK' \
    >"$WORK/session.out" 2>"$WORK/session.err"
rc=$?
if [ "$rc" != 0 ]; then
    echo "---- the operator's stderr, in full:" >&2
    cat "$WORK/session.err" >&2
    echo "---- the node's log, in full:" >&2
    cat "$WORK/serve.log" >&2
    echo "---- who runs this:" >&2; id >&2 2>&1
    echo "---- every component of the ak path:" >&2
    if command -v namei >/dev/null 2>&1; then
        namei -l "$WORK/authorized_keys" >&2 2>&1
    else
        p="$WORK/authorized_keys"
        while [ "$p" != "/" ] && [ -n "$p" ]; do
            stat -c '%a %u:%g %n' "$p" >&2 2>&1
            p=$(dirname "$p")
        done
        stat -c '%a %u:%g %n' / >&2 2>&1
    fi
    fail "ssh exited $rc. The operator's stderr is the diagnosis and it is the
  only channel this has: \`dropssh connect\` IS the ProxyCommand, so stdout is
  the byte pipe to ssh and everything the client knows arrives on stderr."
fi
if ! grep -qx RELAY-LOGIN-OK "$WORK/session.out"; then
    echo "---- stdout:" >&2; cat "$WORK/session.out" >&2
    echo "---- stderr:" >&2; cat "$WORK/session.err" >&2
    fail "ssh exited 0 and the command's output never came back. A session
  that OPENS and delivers nothing is the shape this project has shipped
  twice, and exit 0 is what made it look like a success."
fi
echo "relay-session: a pubkey login to uid $ME_UID completed through $RELAY"

step "a 270 KB transfer, byte for byte, over the same session"
# ⛔ 270528 rather than the 270177 of the 2026-09-28 measurement, and that is
# deliberate: this is 264 KiB, comfortably more than one 65536-byte frame, so
# the relay's CHUNKING is exercised rather than a single frame happening to
# fit. The 2026-09-28 figure is kept in the docs as its own measurement.
dd if=/dev/urandom of="$WORK/payload" bs=1024 count=264 2>/dev/null
SUM=$(sha256sum <"$WORK/payload" | cut -d' ' -f1)
LD_PRELOAD="$D/fakepwd.so" SANDHOME_PASSWD="$WORK/passwd" \
timeout 120 ssh \
    -o "ProxyCommand=$DROPSSH connect --relay $RELAY --name $NAME --token $CONN_TOKEN" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o ConnectTimeout=20 -o LogLevel=ERROR \
    -i "$WORK/user_ed25519" "$ME_NAME@$NAME" 'cat' \
    <"$WORK/payload" >"$WORK/payload.back" 2>"$WORK/transfer.err"
rc=$?
if [ "$rc" != 0 ]; then
    cat "$WORK/transfer.err" >&2
    fail "the transfer exited $rc"
fi
BACK=$(sha256sum <"$WORK/payload.back" | cut -d' ' -f1)
if [ "$SUM" != "$BACK" ]; then
    echo "  sent $(wc -c <"$WORK/payload") bytes, sha256 $SUM" >&2
    echo "  got  $(wc -c <"$WORK/payload.back") bytes, sha256 $BACK" >&2
    fail "a 270 KB transfer did not come back byte for byte. A SHORT result is
  the data-loss class this project hit twice -- a frame clamped to the relay's
  maxFrameBytes loses the remainder with no close and no log, and the only
  symptom is a transfer that stops part way. A CORRUPT result means the id
  prefix is being added or stripped in the wrong place."
fi
echo "relay-session: 270528 bytes came back byte for byte through $RELAY"

step "two sessions overlapping on ONE node socket"
# ⛔ "OVERLAPPING", NOT "CONCURRENT IN A SUBHELL", AND THE MEASUREMENT SAYS WHY.
#
# The first version backgrounded each session in a subshell and used bare
# `wait`. Measured against the live relay: bare `wait` returns when the LAST
# job finishes, so one session finishing early left the other apparently hung
# for the full 60 s timeout and the whole script exited 124 with nothing on
# stderr. ⛔ A HANG THAT REPORTS NOTHING IS A HANG NOBODY CAN DEBUG.
#
# What the multiplexer actually needs is two sessions ALIVE AT ONCE, and the
# measured way to get that is a long-running first session with a short one
# started inside it. Measured on the live relay at 2026-09-28: three
# sequential sessions, one node registration, every reply delivered -- so the
# multiplexer is real and what was broken was the test's wait, not the relay.
# ⛔ A SEQUENTIAL LOOP WOULD NOT TEST ANYTHING: the node's registration count
# below is what distinguishes "multiplexed" from "redialed per session", and
# that is the assertion.
W1=$WORK/s1.out; W2=$WORK/s2.out
env SANDHOME_PASSWD="$WORK/passwd" LD_PRELOAD="$D/fakepwd.so" \
    timeout 90 ssh \
    -o "ProxyCommand=$DROPSSH connect --relay $RELAY --name $NAME --token $CONN_TOKEN" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o ConnectTimeout=20 -o LogLevel=ERROR \
    -i "$WORK/user_ed25519" "$ME_NAME@$NAME" \
    'echo SESSION-A; sleep 8; echo SESSION-A-DONE' >"$W1" 2>"$WORK/s1.err" &
FIRST=$!
# The second session starts while the first is inside its sleep, so both are
# open on the node's single websocket at the same moment.
sleep 2
LD_PRELOAD="$D/fakepwd.so" SANDHOME_PASSWD="$WORK/passwd" \
timeout 40 ssh \
    -o "ProxyCommand=$DROPSSH connect --relay $RELAY --name $NAME --token $CONN_TOKEN" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o ConnectTimeout=20 -o LogLevel=ERROR \
    -i "$WORK/user_ed25519" "$ME_NAME@$NAME" 'echo SESSION-B' >"$W2" 2>"$WORK/s2.err" &
SECOND=$!
wait "$SECOND" 2>/dev/null; second_rc=$?
wait "$FIRST" 2>/dev/null; first_rc=$?
for pair in "A:$W1:$first_rc" "B:$W2:$second_rc"; do
    tag=${pair%%:*}; rest=${pair#*:}; outfile=${rest%%:*}; orc=${rest##*:}
    if ! grep -q "SESSION-$tag" "$outfile" 2>/dev/null; then
        echo "---- session $tag stderr:" >&2; cat "$WORK/s$([ "$tag" = A ] && echo 1 || echo 2).err" >&2
        echo "---- the node's log:" >&2; cat "$WORK/serve.log" >&2
        fail "session $tag did not deliver its output (rc=$orc). Two sessions
  alive at once on one node socket is the only thing that catches a
  multiplexer, and it is the half of the multiplexer this project does not
  implement."
    fi
done
echo "relay-session: two sessions alive at once on one node socket, both delivered"

step "and the node held ONE websocket for both of them"
# ⛔ THE MEASUREMENT IS OF THE NODE'S OWN REGISTRATION COUNT, NOT OF THE
# OPERATOR'S SUCCESS. Two operators both succeeding proves the relay
# multiplexes; it does not prove the NODE did, and a node that redials per
# session is invisible from the outside because every session works.
before=$(grep -c "registered with" "$WORK/serve.log" 2>/dev/null || echo 0)
echo "  the node registered $before time(s) in total, for four sessions"
if [ "$before" -ne 1 ]; then
    fail "the node registered $before times for what should be ONE socket. A
  node that serves a session and redials is the defect B1, and it is invisible
  from the outside because every session works -- which is why the count is
  read from the node's own log and not from the operator's success."
fi
echo "relay-session: the node held one socket"

echo ""
echo "relay-session: $RELAY (version $ver) carried a real pubkey login to uid $ME_UID,"
echo "  a 270 KB transfer byte for byte, and two concurrent sessions on one node"
echo "  socket -- with a pair this run minted for itself, and a server with no"
echo "  LD_PRELOAD in its environment."
exit 0
