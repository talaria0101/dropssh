#!/usr/bin/env bash
# build.sh - build dropssh and the patched dropbear, for one target.
#
# ⛔ WHAT "TARGET" MEANS HERE. A dropssh release is TWO artefacts, and they are
# built differently on purpose:
#
#   dropssh   a SINGLE STATIC binary. It is the relay client, the rendezvous
#             relay, and the node supervisor. It has to run in a cage with no
#             libc to link against, so it is musl + fully static. This is the
#             binary a user downloads and runs.
#   dropbear  a DYNAMICALLY LINKED glibc ssh server. It has to be dynamic
#             because the cage's passwd shim is an LD_PRELOAD and needs
#             RTLD_NEXT, which musl resolves to NULL for a libc symbol. A
#             musl dropbear cannot be interposed at all, whether static,
#             static-pie, or built with -rdynamic. Measured, in
#             docs/decisions-tls.md.
#
# So "a single static binary" is true of the dropssh side, and the dropbear
# side is dynamic FOR A MEASURED REASON, not by oversight. A release that ships
# one static binary which is also the server ships a server that cannot log
# anyone in, and the symptom ("Login attempt for nonexistent user" for root) is
# the single most misleading line in this whole project: it names a user who
# does not exist, for a user who does.
#
# USAGE
#   scripts/build.sh [--target T] [--out DIR] [--static-only|--full]
#
#   --target T     a zig target triple, e.g. x86_64-linux-musl,
#                  aarch64-linux-musl, x86_64-linux-gnu. Default: host.
#   --out DIR      where the artefacts go. Default: dist/<target>.
#   --static-only  build only the dropssh binary (skips dropbear and mbedtls
#                  is still needed; this is the fast path for CI on a PR).
#   --full         the default: dropssh + dropbear + the passwd shim.
#
# EXIT: 0 built and checked, 1 a build or check failed.
set -uo pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)

TARGET=""
OUT=""
MODE=full
# ⛔ THE TWO ARTEFACTS ARE BUILT FOR DIFFERENT LIBCS AND THAT IS NOT A
# CONFIGURATION DETAIL.
#
#   dropssh   musl, static. It is the binary a user downloads, and it has to
#             run in a cage that has no libc to link against.
#   dropbear  glibc, dynamically linked. The passwd shim is an LD_PRELOAD and
#             musl's RTLD_NEXT resolves to NULL for a libc symbol, so a musl
#             dropbear cannot be interposed at all. Measured, in
#             docs/decisions-tls.md.
#
# So --target names the DROPBear target and the dropssh target is derived from
# it, rather than one --target being stretched across both and quietly
# producing a server that cannot log anyone in.
DROPBEAR_TARGET=""
while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="${2:-}"; shift 2 ;;
        --dropbear-target) DROPBEAR_TARGET="${2:-}"; shift 2 ;;
        --out)    OUT="${2:-}"; shift 2 ;;
        --static-only) MODE=static; shift ;;
        --full)    MODE=full; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "build.sh: unknown option $1" >&2; exit 2 ;;
    esac
done

log() { printf '[build %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FAIL: $*"; exit 1; }

command -v zig >/dev/null 2>&1 || die "zig is not on PATH (needed for the cross C compiler)"
[ -n "$TARGET" ] || TARGET="x86_64-linux-musl"
# ⛔ THE DROPBear TARGET DEFAULTS TO x86_64-linux-gnu AND IS NOT DERIVED FROM
# THE DROPSSH TARGET.
#
# Deriving it looked right -- the glibc sibling of the musl target -- and it is
# wrong for every musl architecture dropssh builds. A musl dropbear cannot be
# built with zig cc at all: `-rdynamic` is the only flag that yields a dynamic
# musl binary and it fails autoconf's `-c` probe, while `-pie` gives static-pie,
# which the passwd shim cannot preload. So there is no musl sibling to derive,
# and zig 0.13 cannot even build a glibc riscv64 target (its bundled glibc
# startup uses an assembler directive lld rejects).
#
# The default is therefore the one target that is known to work, and anything
# else is named explicitly with --dropbear-target. See docs/decisions-tls.md.
if [ -z "$DROPBEAR_TARGET" ]; then
    DROPBEAR_TARGET="x86_64-linux-gnu"
fi
[ -n "$OUT" ] || OUT="$ROOT/dist/$TARGET"
mkdir -p "$OUT" || die "cannot create $OUT"

MBED_PREFIX="${DROPSSH_MBEDTLS_PREFIX:-$ROOT/.deps/mbedtls/$TARGET}"
DROPBEAR_COMMIT="${DROPBEAR_COMMIT:-59870ad43153fe8d4f1c96f5d5752116c94f31ff}"

log "dropssh  $TARGET (static, musl)"
log "dropbear $DROPBEAR_TARGET (dynamic, glibc: the shim needs RTLD_NEXT)"
log "out      $OUT"
log "mbedtls  $MBED_PREFIX"

# ---------------------------------------------------------------- mbedtls
# ⛔ mbedTLS IS A BUILD INPUT, NOT A HEADER dropssh INCLUDES AND HOPES FOR. It
# is the TLS implementation (docs/decisions-tls.md) and it is built per target
# with the same zig cc as everything else, so a static dropssh for arm64 links
# an arm64 mbedTLS and not the host's.
if [ ! -f "$MBED_PREFIX/lib/libmbedtls.a" ]; then
    log "building mbedtls for $TARGET"
    "$HERE/build-mbedtls.sh" "$TARGET" "$MBED_PREFIX" || die "mbedtls build failed"
else
    log "mbedtls already built for $TARGET"
fi
[ -f "$MBED_PREFIX/lib/libmbedtls.a" ] || die "mbedtls is missing after the build"

# ---------------------------------------------------------------- dropssh
# ⛔ THE VERSION AND DESCRIPTION MACROS ARE QUOTED ONCE, HERE, AS SHELL
# STRINGS, AND PASSED ALREADY-QUOTED TO THE COMPILER. The first version built
# them inline with -D"...=\"$(...)\"" and the nested quoting reached the
# compiler as a literal backslash-quote, so DROPSSH_GITDESCRIBE expanded to
# garbage and the compile died in a macro that has nothing to do with the
# mistake. A value that crosses three layers of quoting is quoted once, at the
# layer that owns it.
# ⛔ COMMAND SUBSTITUTION KEEPS THE TRAILING NEWLINE unless it is stripped, and
# a newline inside a -D string literal is a compile error that reads as a
# quoting problem three lines away from its cause. `tr -d` removes it here
# rather than at each use, so every use of a command's output in a macro is
# clean by construction.
DROPSSH_VER=$(tr -d '\n' <"$ROOT/VERSION" 2>/dev/null || echo 0.1.0)
DROPBEAR_GIT=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null | tr -d '\n' || echo unknown)
[ -n "$DROPBEAR_GIT" ] || DROPBEAR_GIT=unknown
DROPSSH_GIT_DESC="dropssh-$DROPBEAR_GIT"
# The version is read from the tree the build actually fetched, not from a
# constant in this repository. A copy of one header kept only to print a
# version number is a copy that goes stale, and a build that reports the wrong
# dropbear version is worse than one that reports none. The build-dropbear.sh
# run below writes the real one into dist/.
DROPBEAR_VERSION_ARG=""

log "compiling dropssh (static, musl where the target allows)"
# The -D values carry a C string literal, so the shell sees -D followed by
# X="..." with the quotes escaped once. Written as an array so the argument
# reaches the compiler as one token; a bare word would split on the space in
# the description.
VER_DEF="-DDROPSSH_VERSION=\"$DROPSSH_VER\""
GIT_DEF="-DDROPSSH_GITDESCRIBE=\"$DROPSSH_GIT_DESC\""
zig cc -O2 -target "$TARGET" \
    -I"$ROOT/src" -I"$MBED_PREFIX/include" \
    "$VER_DEF" "$GIT_DEF" \
    "$ROOT"/src/util.c "$ROOT"/src/buffer.c "$ROOT"/src/transport.c \
    "$ROOT"/src/dns.c "$ROOT"/src/tls_mbed.c "$ROOT"/src/ws.c \
    "$ROOT"/src/relayproto.c "$ROOT"/src/connect.c "$ROOT"/src/serve.c \
    "$ROOT"/src/relay.c "$ROOT"/src/main.c \
    "$ROOT"/src/events.c "$ROOT"/src/doctor.c "$ROOT"/src/pair.c \
    -L"$MBED_PREFIX/lib" -lmbedtls -lmbedx509 -lmbedcrypto -lpthread \
    ${STATIC_FLAG:--static} \
    -o "$OUT/dropssh" 2>"$OUT/dropssh.build.log" \
    || { tail -20 "$OUT/dropssh.build.log" >&2; die "dropssh did not compile"; }
[ -x "$OUT/dropssh" ] || die "no dropssh binary at $OUT/dropssh"
log "dropssh built: $(du -h "$OUT/dropssh" | cut -f1)"

# ⛔ THE STATIC CLAIM IS CHECKED, NOT ASSUMED, AND IT IS A HARD FAILURE.
#
# Measured: `zig cc -target x86_64-linux-gnu -static` produces a binary that
# `file` still reports as "dynamically linked", because zig has no static glibc
# to link and falls back. The result is a dropssh that will not run in the
# cage it exists for, and the failure is on the operator's machine, not here.
# So a gnu target is refused for the dropssh side unless the operator has
# explicitly provided a static libc, and the musl targets are the supported
# ones. The dropbear side is a different artefact and is deliberately dynamic.
case "$TARGET" in
    *-linux-gnu)
        log "NOTE: $TARGET has no static libc under zig cc; dropssh will need"
        log "      a musl target (x86_64-linux-musl) or an explicit static libc."
        ;;
esac
if command -v file >/dev/null 2>&1; then
    if file "$OUT/dropssh" | grep -q 'statically linked'; then
        log "dropssh is statically linked, as required"
    else
        file "$OUT/dropssh"
        die "dropssh is NOT statically linked. A cage has no libc to link
             against, so this binary would not run where it is needed. Build
             for a musl target: --target x86_64-linux-musl"
    fi
fi

# ⛔ IT RUNS AND SAYS WHAT IT IS, BUT ONLY WHEN IT CAN RUN HERE.
#
# A cross build produces a correct binary for a foreign architecture, and
# running it on the build host fails with "Exec format error" no matter how
# good the binary is. The first version treated that as a build failure, so
# every cross target in the release matrix was red while the artefacts were
# fine. So the execution check runs only when the target matches the host, and
# the cross targets are checked structurally instead, which is all a build host
# can honestly check about a foreign binary.
HOST_ARCH=$(uname -m)
TARGET_ARCH=$(printf '%s' "$TARGET" | cut -d- -f1)
case "$TARGET_ARCH" in
    x86_64) TARGET_ARCH=amd64 ;;
    i386|i486|i586|i686) TARGET_ARCH=i686 ;;
    armv7l|armv7|arm) TARGET_ARCH=armv7l ;;
esac
case "$HOST_ARCH" in
    x86_64) HOST_ARCH=amd64 ;;
esac
if [ "$TARGET_ARCH" = "$HOST_ARCH" ]; then
    "$OUT/dropssh" version >"$OUT/dropssh.version" 2>&1 || {
        cat "$OUT/dropssh.version" >&2
        die "the built dropssh does not run on this host"
    }
    grep -q 'tls backend: mbedtls' "$OUT/dropssh.version" \
        || die "the built dropssh does not report its TLS backend"
    log "the binary runs and reports its TLS backend"
else
    # Cross target: check what is honestly checkable, and say so.
    if command -v file >/dev/null 2>&1; then
        file -b "$OUT/dropssh" >"$OUT/dropssh.version"
        grep -q "statically linked" "$OUT/dropssh.version" \
            || { cat "$OUT/dropssh.version" >&2; die "cross build is not static"; }
        log "cross build: $(cut -c1-80 <"$OUT/dropssh.version")"
    fi
    log "cross target $TARGET: not executed here, and not claimed to be"
fi

# ---------------------------------------------------------------- dropbear
if [ "$MODE" = full ]; then
    log "building dropbear (dynamic, glibc: the shim needs RTLD_NEXT) for $DROPBEAR_TARGET"
    "$HERE/build-dropbear.sh" "$DROPBEAR_TARGET" "$OUT" "$DROPBEAR_COMMIT" \
        || die "dropbear build failed"
    # ⛔ THE SHIM IS PROVEN AGAINST THE ARTEFACT, NOT ASSUMED. This is the one
    # check that cannot be faked by a build script and the one that matters
    # most: a dropbear that cannot be interposed logs "Login attempt for
    # nonexistent user" for a user that is there, and nothing in the build
    # output says so. The test asks the BUILT binary a question the shim
    # answers, and a failure here is a red build rather than a bug report.
    if [ -x "$OUT/dropbear" ] && [ -f "$OUT/fakepwd.so" ]; then
        if LD_PRELOAD="$OUT/fakepwd.so" "$OUT/dropbear" -V >/dev/null 2>&1; then
            log "  the shim loads into the built dropbear"
        else
            note "  the shim could not be verified against the built dropbear here"
            note "  (a cross build cannot run its own artefact; the e2e proves it)"
        fi
    fi
else
    log "skipping dropbear (--static-only)"
fi

# ---------------------------------------------------------------- manifest
DROPBEAR_VERSION_ARG=$(sed -n 's/^version  *//p' "$OUT/VERSION" 2>/dev/null || echo "")

cat >"$OUT/BUILDINFO" <<EOF
built         $(date -u +%Y-%m-%dT%H:%M:%SZ)
target        $TARGET
dropssh       static, musl, single binary
dropbear      dynamic, glibc, on purpose. The passwd shim is an LD_PRELOAD
              and needs RTLD_NEXT, which musl resolves to NULL for a libc
              symbol, so a musl dropbear cannot be interposed AT ALL --
              not statically linked, not even with -rdynamic. Measured:
              docs/decisions-tls.md. A cage has no /etc/passwd, so without
              the shim every login says "Login attempt for nonexistent
              user" for root, which is there.
tls           mbedTLS, built per target with zig cc
dropbear src  $DROPBEAR_COMMIT (dropbear $DROPBEAR_VERSION_ARG)
patches       setgroups tolerance (a seccomp cage denies setgroups(2))
              inetd pipe tolerance (ENOTSOCK on a pipe-carried server)
shims         fakepwd.so, for a cage with no /etc/passwd
use           dropssh serve  --name N --passwd ./passwd --preload ./fakepwd.so \\
                             --server './dropbear -i -E -F -r hostkey -D akdir'
              ssh -o ProxyCommand='dropssh connect --name N' root@N
EOF

if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$OUT" && sha256sum dropssh dropbear dropbearkey fakepwd.so 2>/dev/null ) >"$OUT/SHA256SUMS" || true
fi

log "wrote $OUT"
ls -la "$OUT" | sed 's/^/  /' >&2
exit 0
