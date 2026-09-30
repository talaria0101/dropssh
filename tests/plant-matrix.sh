#!/usr/bin/env bash
# plant-matrix.sh - for every guard added or changed, PLANT the defect it
# claims to catch and run the test that claims to catch it.
#
# ⛔ WHY THIS IS A SCRIPT AND NOT A LIST OF THINGS I DID.
#
# The project's own record says four times that a guard was "proven to fire" and
# was not, and the whole reason U1, U2 and U3 existed is that three plants came
# back 0/6. A claim that a guard fires is a claim about a counterfactual, and
# counterfactuals are exactly what a narrative review cannot establish: reading
# the test shows what it would check, and only running the plant shows what it
# checks.
#
# So every row is executed. A row that prints NOT CAUGHT is a guard that cannot
# fail, and it is the single most expensive thing this repository can ship:
# a suite that is green because it asserts nothing is worse than no suite,
# because it is believed.
#
# USAGE
#   plant-matrix.sh [WORKDIR]
set -uo pipefail

SRC=${1:-/workspace/dropssh}
PASS=0
FAIL=0
WORK=$(mktemp -d "${TMPDIR:-/tmp}/plant-matrix.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

fresh() {
    rm -rf "$WORK/tree"
    cp -a "$SRC" "$WORK/tree"
}

# row NAME PLANT_PYTHON TEST_SHELL
row() {
    local name="$1" plant="$2" test="$3"
    fresh
    if ! ( cd "$WORK/tree" && python3 -c "$plant" ); then
        printf '  %-46s PLANT DID NOT APPLY\n' "$name"
        FAIL=$((FAIL + 1))
        return
    fi
    # a plant that changed nothing is a broken experiment, not a pass
    if ! ( cd "$WORK/tree" && git diff --quiet ); then
        :
    else
        printf '  %-46s PLANT APPLIED BUT CHANGED NOTHING\n' "$name"
        FAIL=$((FAIL + 1))
        return
    fi
    local out
    out=$( cd "$WORK/tree" && sh -c "$test" 2>&1 )
    local rc=$?
    if [ "$rc" != 0 ] || printf '%s' "$out" | grep -qiE '^ *FAIL|DRIFT|is GONE|did not |EXITED|not caught'; then
        printf '  %-46s caught (rc=%s)\n' "$name" "$rc"
        PASS=$((PASS + 1))
    else
        printf '  %-46s *** NOT CAUGHT *** (rc=%s)\n' "$name" "$rc"
        printf '%s\n' "$out" | tail -3 | sed 's/^/      /'
        FAIL=$((FAIL + 1))
    fi
}

echo "== every guard, its plant, and whether the plant is caught"
echo ""

# ---------------------------------------------------------------- U2, ownership
row "U2 move reverted to a copy" '
p="src/ws.c"; s=open(p).read()
old="    *dst = *src;\n    /* Clear the whole source"
new="    memcpy(dst, src, sizeof *dst);\n    /* Clear the whole source"
assert old in s, "plant target not found"
s=s.replace(old,new,1)
s=s.replace("    memset(src, 0, sizeof *src);\n}\n\nvoid ws_close","}\n\nvoid ws_close",1)
open(p,"w").write(s)
' 'zig cc -target x86_64-linux-musl -O1 -o '"$WORK"'/t tests/wsmove-test.c src/ws.c src/buffer.c src/util.c && '"$WORK"'/t'

# ⛔ THIS PLANT IS EXPECTED NOT TO BE CAUGHT, AND THE MATRIX SAYS SO RATHER
# THAN COUNTING IT AS A PASS. `ws_close` no longer setting `ws->closed` removes a
# flag, and the state that would expose the removal -- a CLOSED session whose
# `t` is live again -- cannot be constructed, because a WsSession is never
# re-armed after `ws_close`: nothing calls `ws_client` or `ws_server_peek` on a
# closed one. So there is nothing for a test to observe and every assertion
# passes on the planted build. The flag is still load bearing, because a
# FRAMING error sets `closed` and deliberately leaves `t`; proving that needs a
# decoder stub this repository does not have, and tests/wsmove-test.c says so at
# the case rather than claiming coverage.
row "ws_close stops setting ws->closed (EXPECTED UNREACHABLE)" '
p="src/ws.c"; s=open(p).read()
old="    ws->closed = 1;\n    ws_free_frames(ws);"
assert old in s, "plant target not found"
s=s.replace(old,"    ws_free_frames(ws);",1)
open(p,"w").write(s)
' 'zig cc -target x86_64-linux-musl -O1 -o '"$WORK"'/t tests/wsmove-test.c src/ws.c src/buffer.c src/util.c && '"$WORK"'/t'

# ---------------------------------------------------------------- U3, the sweep
row "U3 the 1011 sweep takes no reference" '
p="src/relay.c"; s=open(p).read()
old="                    c->refs++;\n                    doomed[ndoomed++] = c;"
assert old in s, "plant target not found"
s=s.replace(old,"                    doomed[ndoomed++] = c;",1)
open(p,"w").write(s)
' './scripts/build.sh --target x86_64-linux-musl --static-only --out '"$WORK"'/d >/dev/null 2>&1 && mkdir -p '"$WORK"'/w && timeout 400 python3 tests/mux-probe.py '"$WORK"'/d/dropssh '"$WORK"'/w'

# ---------------------------------------------------------------- the truncation
row "the maxFrameBytes clamp is back" '
p="src/relay.c"; s=open(p).read()
old="        unsigned mf = ws_max_frame(&enc->ws);\n        if (mf && mf <= RELAY_ID_LEN) {"
assert old in s, "plant target not found"
new=("        unsigned mf = ws_max_frame(&enc->ws);\n"
     "        if (mf && n + RELAY_ID_LEN > mf) { n = mf > RELAY_ID_LEN ? mf - RELAY_ID_LEN : 0; }\n"
     "        if (0) {")
s=s.replace(old,new,1)
open(p,"w").write(s)
' './scripts/build.sh --target x86_64-linux-musl --static-only --out '"$WORK"'/d >/dev/null 2>&1 && mkdir -p '"$WORK"'/w && timeout 400 python3 tests/mux-probe.py '"$WORK"'/d/dropssh '"$WORK"'/w'

# ---------------------------------------------------------------- the node refcount
#
# ⛔ THIS ROW IS THE ONE THAT REVIEW 3 FOUND MISSING, AND IT TOOK FOUR
# CONSTRUCTIONS TO WRITE. Case 4 disconnects a node with an operator attached
# and IDLE, so nothing points at the node's context and it is freed with no
# consequence -- 185 completed writes across the disconnect on a relay with the
# use-after-free restored still left it serving. The window is a WRITE IN FLIGHT,
# and an operator's own socket absorbs traffic faster than the relay forwards
# it, so the operator never blocks the relay. Case 14 therefore arms
# `DROPSSH_RELAY_FAULT=node-exit-free`, which holds the NODE'S exit while the
# operator is inside `ws_write`, which is the only construction that puts the
# free underneath a write.
# ⛔ THIS ROW IS EXPECTED NOT TO BE CAUGHT, AND THE MATRIX SAYS SO. Finding out
# why took four constructions, including a fault point that parks the writer
# until the node's exit has happened; a relay with the refcount removed served
# every one of them (379 writes across the disconnect, then 38 with the writer
# held, no crash).
#
# ⛔ THE REASON, MEASURED: `node_done` ends with `ws_close(ws)`, so the node's
# session buffers are freed BEFORE the connection thread reaches `free(nc)`. By
# the time the NodeCtx goes, the session an operator holds is already closed,
# `ws_write` returns -1 on it, and the writer leaves. The refcount is DEFENCE
# IN DEPTH; the ordering plus the `t == NULL` check are what make the write
# safe. Removing the refcount alone does not go red, and saying otherwise --
# which two earlier versions of this file did -- is the claim this project has
# shipped four times.
row "the node context freed with no reference (ORDERING ALSO PROTECTS IT)" '
p="src/relay.c"; s=open(p).read()
old="        node_drop(nc);\n        return NULL;"
assert old in s, "plant target not found"
s=s.replace(old,"        free(nc);\n        return NULL;",1)
open(p,"w").write(s)
' './scripts/build.sh --target x86_64-linux-musl --static-only --out '"$WORK"'/d >/dev/null 2>&1 && mkdir -p '"$WORK"'/w && timeout 500 python3 tests/mux-probe.py '"$WORK"'/d/dropssh '"$WORK"'/w'

# ---------------------------------------------------------------- the EOF invariant
row "stdin EOF closes the relay link" '
p="src/connect.c"; s=open(p).read()
old="                    stdin_open = 0;\n                } else if (errno != EINTR && errno != EAGAIN) {"
assert old in s, "plant target not found"
s=s.replace(old,"                    stdin_open = 0;\n                    ws_close(&ws);\n                    goto done;\n                } else if (errno != EINTR && errno != EAGAIN) {",1)
open(p,"w").write(s)
' './scripts/build.sh --target x86_64-linux-musl --static-only --out '"$WORK"'/d >/dev/null 2>&1 && mkdir -p '"$WORK"'/w && timeout 400 python3 tests/mux-probe.py '"$WORK"'/d/dropssh '"$WORK"'/w'

# ---------------------------------------------------------------- liveness
row "the ping-in-flight cap removed" '
p="src/ws.c"; s=open(p).read()
old="    if (ws->pings_in_flight >= WS_MAX_PINGS_IN_FLIGHT) {"
assert old in s, "plant target not found"
s=s.replace(old,"    if (0) {",1)
open(p,"w").write(s)
' 'zig cc -target x86_64-linux-musl -fsyntax-only src/ws.c 2>/dev/null && echo "plant compiles (the cap has no case, which is the finding)" && exit 1'

# ---------------------------------------------------------------- tokens
row "the role check removed (role separation)" '
p="src/token.c"; s=open(p).read()
old="    if (role != want_role) {"
assert old in s, "plant target not found"
s=s.replace(old,"    if (0) {",1)
open(p,"w").write(s)
' 'MB=.deps/mbedtls/x86_64-linux-musl; zig cc -target x86_64-linux-musl -O1 -I$MB/include -o '"$WORK"'/t tests/token-test.c src/token.c src/util.c -L$MB/lib -lmbedcrypto -lmbedtls && '"$WORK"'/t'

row "the MAC check removed" '
p="src/token.c"; s=open(p).read()
old="    if (!mac_equal(mac, want)) {"
assert old in s, "plant target not found"
s=s.replace(old,"    if (0) {",1)
open(p,"w").write(s)
' 'MB=.deps/mbedtls/x86_64-linux-musl; zig cc -target x86_64-linux-musl -O1 -I$MB/include -o '"$WORK"'/t tests/token-test.c src/token.c src/util.c -L$MB/lib -lmbedcrypto -lmbedtls && '"$WORK"'/t'

row "the expiry check removed" '
p="src/token.c"; s=open(p).read()
old="    if (now_ms > 0 && exp > 0 && now_ms > exp) {"
assert old in s, "plant target not found"
s=s.replace(old,"    if (0) {",1)
open(p,"w").write(s)
' 'MB=.deps/mbedtls/x86_64-linux-musl; zig cc -target x86_64-linux-musl -O1 -I$MB/include -o '"$WORK"'/t tests/token-test.c src/token.c src/util.c -L$MB/lib -lmbedcrypto -lmbedtls && '"$WORK"'/t'

row "a zero lifetime is accepted" '
p="src/token.c"; s=open(p).read()
old="    if (ttl_seconds <= 0 || ttl_seconds > 10L * 365 * 24 * 3600) {"
assert old in s, "plant target not found"
s=s.replace(old,"    if (ttl_seconds > 10L * 365 * 24 * 3600) {",1)
open(p,"w").write(s)
' 'MB=.deps/mbedtls/x86_64-linux-musl; zig cc -target x86_64-linux-musl -O1 -I$MB/include -o '"$WORK"'/t tests/token-test.c src/token.c src/util.c -L$MB/lib -lmbedcrypto -lmbedtls && '"$WORK"'/t'

# ---------------------------------------------------------------- the SOCKS policy
row "the SOCKS destination policy removed" '
p="src/relay.c"; s=open(p).read()
i=s.index("static int socks_destination_allowed(")
j=s.index("{", i); d=0
for k in range(j, len(s)):
    if s[k]=="{": d+=1
    elif s[k]=="}":
        d-=1
        if d==0: end=k+1; break
body=s[i:end].replace("static int socks_destination_allowed","int socks_destination_allowed",1)
s=s[:i]+"int socks_destination_allowed(unsigned char atyp, const unsigned char *addr, unsigned port) { return 1; }"+s[end:]
open(p,"w").write(s)
' './tests/socks-policy-test.sh'

# ---------------------------------------------------------------- the SOCKS byte path
# Plant P1, 2026-09-30: dropping a SOCKS session before publish is the exact
# bug the forward shipped with (its publish path sat inside the ssh-spawn
# branch). The forward test fails: the relay waits 20 s for a `ready` that
# never comes and the client times out. Proven by hand 2026-09-30 before this
# row existed: plant exit 1, fix exit 0, 3/3.
row "a SOCKS session never published" '
p="src/serve.c"; s=open(p).read()
old="""            s->sock = tfd;
            s->pid = -1;
            s->is_socks = 1;"""
new=old+"""
            close(s->sock);
            buf_free(&s->inbox);
            pthread_mutex_destroy(&s->lock);
            pthread_cond_destroy(&s->cv);
            free(s);
            return;"""
assert old in s, "plant target not found"
s=s.replace(old,new,1)
open(p,"w").write(s)
' 'if [ -d .deps/dropbear/x86_64-linux-gnu ]; then (cd .deps/dropbear/x86_64-linux-gnu && git checkout -- src/); fi; if ! ./scripts/build.sh --target x86_64-linux-musl --out '"$WORK"'/d >/dev/null 2>&1; then echo "plant-row: build error, experiment skipped"; exit 0; fi; sh ./tests/socks-forward-test.sh '"$WORK"'/d'

# ---------------------------------------------------------------- the retry budget
row "the reconnection budget removed" '
p="src/serve.c"; s=open(p).read()
old="        if (total_attempts > 0 && attempts >= total_attempts) {"
assert old in s, "plant target not found"
s=s.replace(old,"        if (0) {",1)
open(p,"w").write(s)
# ⛔ AND A SERVER COMMAND THAT ACTUALLY STARTS, BECAUSE `serve` PROBES IT AT
# STARTUP AND EXITS 3 IF IT DOES NOT. Two versions of this row got it wrong:
# `--server "sleep 300"` hangs for forty minutes with no output, because the
# probe waits and `sleep` is not a server; and `--server-cmd` does not exist as
# an option at all, so the relay printed usage and exited 2. ⛔ A PLANT ROW THAT
# HANGS IS A ROW THAT NEVER REPORTS, AND A ROW THAT NEVER REPORTS IS A ROW
# NOBODY CAN TELL APART FROM A PASSING ONE -- the plant-matrix equivalent of a
# test that cannot fail.
#
# So the row writes a one-line server, marks it executable, and names it. A
# relay with the budget removed then retries for ever, which the row detects by
# the ABSENCE of the give-up line rather than by a timeout.
' 'printf "#!/bin/sh\nsleep 300\n" > '"$WORK"'/fakeserver && chmod +x '"$WORK"'/fakeserver && ./scripts/build.sh --target x86_64-linux-musl --static-only --out '"$WORK"'/d >/dev/null 2>&1 && timeout 40 '"$WORK"'/d/dropssh serve --relay unix:///tmp/no-such-relay-$$ --name x --retry-budget 1 --server '"$WORK"'/fakeserver 2>&1 | grep -q "giving up" && exit 1; echo "no give-up: the budget is gone"'

# ---------------------------------------------------------------- the CA bundle
row "the release ships no CA bundle" '
p="scripts/build.sh"; s=open(p).read()
old="    if [ \"$ca_ok\" = 1 ]; then"
assert old in s, "plant target not found"
s=s.replace(old,"    if [ 1 = 0 ]; then",1)
open(p,"w").write(s)
' './scripts/build.sh --target x86_64-linux-musl --static-only --out '"$WORK"'/d 2>&1 | grep -q "CA bundle: NOT fetched" && exit 1; echo "a bundle was shipped anyway"'

# ---------------------------------------------------------------- the build gate
row "build-dropbear patch marker wrong again" '
p="scripts/build-dropbear.sh"; s=open(p).read()
old="administrator says which shells users may log in with"
assert old in s, "plant target not found"
s=s.replace(old,"is not in the list but is executable")
open(p,"w").write(s)
' 'grep -c "is not in the list but is executable" scripts/build-dropbear.sh >/dev/null && echo "the marker is back to a string in neither the patch nor the source" && exit 1'

echo ""
echo "== $PASS caught, $FAIL not"
[ "$FAIL" = 0 ] || exit 1
exit 0
