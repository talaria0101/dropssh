#!/bin/sh
# fetch-relay-spec.sh - fetch the relay's OWN protocol document, and record
# which VERSION it came from. R8.
#
# ⛔ WHY THE SERVED DOCUMENT AND NOT A GIT PIN.
#
# R8 asked for the reference operator "fetched, pinned", modelled on how the
# sandhome shims are fetched. Reading the relay's own reply on issue #9 shows
# why that is the wrong shape: there is no repository in this project to pin.
# The relay publishes a Cloudflare Worker, and what it serves at
# tcp.ssh.relay.ajam.dev is the thing a client actually talks to. A pin against
# a repository would record what the source said on a day; this records what the
# deployment is serving now, WITH ITS VERSION, which is the thing that can
# change under us.
#
# ⛔ AND DRIFT HAS ALREADY HAPPENED, which is the argument for fetching at all.
# Measured: /health reported `2026-09-28-r11` when this project's measurements
# were taken, and `2026-09-28-r12` when this script was written, the same day.
# A2 -- "the operator's leg is data-only" -- was added between them, in
# response to our own issue. Nothing in this repository would have noticed: our
# client already works around it by never sending control on that leg, so a
# change to the protocol is invisible here until it becomes a close code.
#
# ⛔ THE OUTPUT IS A DOCUMENT, NOT A BINARY, AND NOT A TEST. It is reference
# material for a reader and for the next reviewer. Nothing parses it, because
# parsing a peer's prose specification and asserting our client against it would
# be a conformance suite we would then have to keep correct when the peer
# rewords a sentence. What IS asserted is the VERSION and the presence of the
# facts we hold a measured opinion about, so a change in either is visible in a
# diff rather than discovered.
#
# USAGE
#   fetch-relay-spec.sh [OUTDIR]
#
# EXIT
#   0  fetched, and the recorded facts still hold
#   1  fetched, and a recorded fact CHANGED -- a drift report, not a failure
#   2  could not fetch, or the endpoint is not the shape we expect
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
OUT="${1:-$ROOT/docs/relay-spec}"
BASE="${DROPSSH_RELAY_SPEC_BASE:-https://tcp.ssh.relay.ajam.dev}"

mkdir -p "$OUT" || exit 2

if ! command -v curl >/dev/null 2>&1; then
    echo "fetch-relay-spec: no curl on this host, so the relay's own document" >&2
    echo "  cannot be fetched. The copy in docs/relay-spec/ is from when it was" >&2
    echo "  last run; the version in RELAY-SPEC-VERSION says when that was." >&2
    exit 2
fi

# The version first, because everything else is "as of" that. If the fetch of
# the document succeeds and the version does not, the document is recorded with
# an unknown version rather than not recorded at all -- a document with a
# missing provenance is more useful than no document, PROVIDED it says so.
ver="unknown"
if curl -fsSL --max-time 30 "$BASE/health" -o "$OUT/health.json" 2>/dev/null; then
    v=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$OUT/health.json" 2>/dev/null | head -1)
    [ -n "$v" ] && ver="$v"
fi

ok=1
for doc in llms-full.txt index.md; do
    if curl -fsSL --max-time 60 "$BASE/$doc" -o "$OUT/$doc" 2>/dev/null && \
       [ -s "$OUT/$doc" ]; then
        echo "fetch-relay-spec: $doc, $(( $(wc -l <"$OUT/$doc") )) lines, relay version $ver"
    else
        echo "fetch-relay-spec: could not fetch $doc" >&2
        ok=0
    fi
done
[ "$ok" = 1 ] || exit 2

# ⛔ THE RECORDED FACTS ARE THE ONES THIS PROJECT HOLDS A MEASURED OPINION
# ABOUT, and each is a string we would have to get wrong to fail. They are not
# a conformance suite and are not one: a peer rewording a sentence must not turn
# this into a red build, and only a change in the PROTOCOL should.
#
# Each fact is the exact token this repository's measurements used. If a future
# version of the relay renames one, the fact stops matching and the diff says so
# -- which is the entire point of fetching it.
drift=0
check() {
    _label="$1"; _pattern="$2"; _file="$3"
    if grep -q -- "$_pattern" "$OUT/$_file" 2>/dev/null; then
        printf '  ok    %-34s present in %s\n' "$_label" "$_file"
    else
        printf '  DRIFT %-34s NOT in %s\n' "$_label" "$_file"
        drift=$((drift + 1))
    fi
}
echo "fetch-relay-spec: the facts this repository measured, re-checked against $ver"
check "reverse node path"        'v1/node'                 llms-full.txt
check "reverse operator path"    'v1/connect'              llms-full.txt
check "bare node frame is 1009"  'bad multiplex frame'     llms-full.txt
check "text on a data leg"       'binary frames required'  llms-full.txt
check "unanswered open"          'node open timeout'       llms-full.txt

cat >"$OUT/RELAY-SPEC-VERSION" <<EOF
relay            $BASE
version          $ver
fetched          $(date -u +%Y-%m-%dT%H:%M:%SZ)
facts_checked    5
facts_drifted    $drift
EOF

echo "fetch-relay-spec: wrote $OUT/RELAY-SPEC-VERSION"
if [ "$drift" != 0 ]; then
    echo "" >&2
    echo "fetch-relay-spec: $drift of the 5 recorded facts NO LONGER HOLD." >&2
    echo "  That is not a failure of this script; it is the relay changing, or" >&2
    echo "  re-wording, something this repository measured and wrote down." >&2
    echo "  Read the diff, then either re-measure and update the docs, or" >&2
    echo "  record why the new form is equivalent. Do not re-pin silently." >&2
    exit 1
fi
exit 0
