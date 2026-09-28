#!/bin/sh
# socks-policy-test.sh - build and run the SOCKS5 destination policy test.
#
# ⛔ THE FUNCTION UNDER TEST IS EXTRACTED FROM src/relay.c AT BUILD TIME, AND
# THE EXTRACTION FAILS LOUDLY IF IT CANNOT FIND IT.
#
# The obvious way to write this test is to copy the policy into the test file.
# That test then passes when the product is wrong, which is the failure this
# repository has shipped four times: a guard built on something other than the
# thing it names. So the function is lifted out of the real source, made
# non-static, and included. A rename or a deletion in relay.c breaks the build
# here rather than leaving a test that has been asserting a dead copy since
# the day somebody edited the product.
#
# ⛔ AND THE SCOPE IS STATED, BECAUSE A UNIT TEST ON A LISTENER IS NOT A TEST OF
# A LISTENER. This asserts the DECISION -- is this destination the one the
# operator named -- and that decision is the whole security of the feature. It
# does not assert that the SOCKS5 wire format is parsed correctly, that a
# forward reaches a node, or that bytes move: dropssh#6 measured 24/24 that a
# reference cage cannot bind INET at all, so none of those can be tested on
# the machine this project develops on, and a test that claims to cover them
# without running them is the thing this repository keeps refusing to write.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
GEN="${TMPDIR:-/tmp}/dropssh-socks-policy-$$.h"

# Extract the function. The brace count is the parse: a hand-written marker
# would drift the first time somebody reformatted the comment above it.
if ! python3 - "$ROOT/src/relay.c" "$GEN" <<'PY'
import sys
src = open(sys.argv[1]).read()
i = src.find("static int socks_destination_allowed(")
if i < 0:
    sys.stderr.write("socks-policy-test: src/relay.c no longer has "
                     "socks_destination_allowed. The policy moved or was "
                     "renamed, and this test asserts THAT function, so it is "
                     "refusing to pass against a copy of something else.\n")
    sys.exit(1)
j = src.index("{", i)
depth = 0
end = None
for k in range(j, len(src)):
    if src[k] == "{":
        depth += 1
    elif src[k] == "}":
        depth -= 1
        if depth == 0:
            end = k + 1
            break
if end is None:
    sys.stderr.write("socks-policy-test: could not find the end of "
                     "socks_destination_allowed in src/relay.c\n")
    sys.exit(1)
body = src[i:end].replace("static int socks_destination_allowed",
                          "int socks_destination_allowed", 1)
with open(sys.argv[2], "w") as f:
    f.write("/* GENERATED from src/relay.c. Do not edit. */\n")
    f.write("#ifndef SOCKS_POLICY_GEN_H\n#define SOCKS_POLICY_GEN_H\n")
    f.write("static char socks_host[256] = \"\";\nstatic int socks_port = 0;\n\n")
    f.write(body)
    f.write("\n#endif\n")
PY
then
    exit 1
fi

BIN="${TMPDIR:-/tmp}/dropssh-socks-policy-$$"
# The generated header is copied next to the test so `#include "..."` finds it
# without -I, which keeps the include line in the test file honest about what it
# is including.
cp "$GEN" "$HERE/socks_policy_gen.h"
if ! zig cc -O1 -o "$BIN" "$HERE/socks-policy-test.c" 2>"$BIN.log"; then
    echo "socks-policy-test: did not compile"
    cat "$BIN.log" >&2
    rm -f "$GEN" "$HERE/socks_policy_gen.h" "$BIN" "$BIN.log"
    exit 1
fi
rm -f "$GEN" "$HERE/socks_policy_gen.h"
"$BIN"
rc=$?
# ⛔ THE BINARY LIVES IN $TMPDIR AND NOT IN THE WORK DIRECTORY, because
# $HOME on the machine this was written on is a mount that refuses to execute a
# file created in it: a mode-0755 binary there answers "Permission denied" and
# the suite would report a policy failure that is a filesystem fact.
if [ "$rc" != 0 ]; then
    echo "socks-policy-test: the SOCKS5 destination policy is not enforced as measured above"
fi
rm -f "$BIN" "$BIN.log"
exit $rc
