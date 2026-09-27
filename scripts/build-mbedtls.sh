#!/usr/bin/env bash
# build-mbedtls.sh - build mbedTLS for one target, with zig cc.
#
# ⛔ THE FRAMEWORK SUBMODULE IS A SEPARATE REPOSITORY AND THE PIN IS A COMMIT.
# mbedTLS's build generates its configuration from a Python module that is not
# in the release tarball at all; it lives in Mbed-TLS/mbedtls-framework and
# mbedtls-3.6.4's submodule ref names one commit of it. Without that commit the
# configure step dies with:
#
#     ModuleNotFoundError: No module named 'mbedtls_framework'
#
# which names a Python module and not the repository that holds it, so the fix
# is a two-hop lookup: read the submodule ref out of the mbedtls tree, then
# fetch THAT commit of the framework repo. Both are pinned here so a build is
# reproducible, and both are checked out by commit rather than by branch.
#
# USAGE: build-mbedtls.sh TARGET PREFIX
set -uo pipefail

PREFIX="${2:?prefix required}"

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
# ⛔ THE SOURCE TREE IS PER TARGET, NOT SHARED.
#
# A shared checkout of mbedTLS looks harmless and is not: cmake writes into the
# tree it is configuring (generated headers, the build tree it is told to use,
# and the framework it stages), so five targets configuring one tree at once
# overwrite each other's files. The symptoms are whatever the losing write
# happened to break:
#
#   Specify --help for usage, or press the help button for the CMake GUI.
#   cp: preserving times for '.../framework.tmp': No such file or directory
#   fatal: destination path '.../mbedtls-3.6.4' already exists
#
# All three name a file and none names two builds. One tree per target costs a
# few megabytes per architecture and removes the entire class.
# The checkout helpers live in one place because every clone in this script had
# the same defect: clone-into-place, and a second build arriving mid-clone finds
# a directory that exists and is not empty. Each clone therefore goes to a
# temporary name and is renamed into place, which is atomic. With one tree per
# target the clone no longer races, and the rename makes a killed build leave
# nothing half-finished.
clone_atomic() {   # clone_atomic URL REF DEST [BRANCH]
    local url="$1" ref="$2" dest="$3" branch="${4:-}"
    [ -d "$dest" ] && return 0
    local tmp="$dest.$$.tmp"
    rm -rf "$tmp"
    if [ -n "$branch" ]; then
        git clone -q --depth 1 --branch "$branch" "$url" "$tmp" || { rm -rf "$tmp"; return 1; }
    else
        git clone -q --depth 1 "$url" "$tmp" || { rm -rf "$tmp"; return 1; }
        git -C "$tmp" checkout -q "$ref" 2>/dev/null || true
    fi
    rm -rf "$dest"
    mv "$tmp" "$dest"
    return 0
}

TARGET="${1:?target required}"
MT_VERSION=3.6.4
MT_TAG="mbedtls-$MT_VERSION"
FW_COMMIT=2a3e2c5ea053c14b745dbdf41f609b1edc6a72fa

# WORK IS DERIVED FROM TARGET, so it is set after TARGET and not with the
# target-independent constants above.
WORK="$ROOT/.deps/mbedtls/$TARGET"

log() { printf '[mbedtls %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FAIL: $*"; exit 1; }

command -v git >/dev/null 2>&1 || die "git is required"
command -v cmake >/dev/null 2>&1 || die "cmake is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required (mbedtls's config generator)"

mkdir -p "$WORK" || die "cannot create $WORK"

# ------------------------------------------------------------------ source
SRC="$WORK/$MT_TAG"
# ⛔ THE CHECKOUT IS TAKEN WITH A LOCK, BECAUSE TWO TARGETS BUILDING AT ONCE
# RACE ON THE CLONE AND ONE OF THEM LOSES THE WORK TREE.
#
#   fatal: could not create work tree dir '.../mbedtls-3.6.4': File exists
#
# which names a directory and not the concurrency that caused it. The matrix
# builds several targets at once on purpose, so this is the normal case and not
# a corner. mkdir is the lock: it is atomic, it needs no lockfile to clean up,
# and a stale one from a killed build is removed by the age check below.
LOCKDIR="$WORK/.checkout.lock"
LOCKAGE=0
if [ -d "$LOCKDIR" ]; then
    LOCKAGE=$(( $(date +%s) - $(stat -c %Y "$LOCKDIR" 2>/dev/null || echo 0) ))
fi
if [ -d "$LOCKDIR" ] && [ "$LOCKAGE" -lt 600 ]; then
    log "another build is fetching mbedtls; waiting"
    i=0
    while [ -d "$LOCKDIR" ] && [ $i -lt 120 ]; do
        sleep 5
        i=$((i+1))
    done
fi
mkdir -p "$WORK"
if [ ! -d "$LOCKDIR" ]; then
    mkdir "$LOCKDIR" 2>/dev/null || true
    if [ ! -d "$SRC" ]; then
        log "fetching mbedtls $MT_VERSION"
        # ⛔ THE CLONE GOES TO A TEMPORARY NAME AND IS RENAMED INTO PLACE, SO A
        # HALF-FINISHED CLONE IS NEVER VISIBLE AS THE SOURCE TREE.
        #
        # Cloning straight into $SRC and deleting it first is the obvious
        # version and it loses twice: a second build that arrives while the
        # first is cloning finds a directory that exists and is not empty, and
        #
        #   fatal: destination path '.../mbedtls-3.6.4' already exists and is
        #   not an empty directory
        #
        # names a directory and not the two builds. The rename is atomic, so
        # $SRC either does not exist or is a complete tree, and a failed clone
        # leaves a temp directory that the next run removes.
        if ! clone_atomic https://github.com/Mbed-TLS/mbedtls "$MT_TAG" "$SRC" "$MT_TAG"; then
            rmdir "$LOCKDIR" 2>/dev/null || true
            die "cannot fetch mbedtls $MT_TAG"
        fi
    fi
    rmdir "$LOCKDIR" 2>/dev/null || true
fi

# The framework is a separate repository at a pinned commit. The submodule ref
# is read from the mbedtls tree so the pin follows upstream rather than
# drifting from it, and falls back to the constant here.
WANT=$(git -C "$SRC" ls-tree HEAD framework 2>/dev/null | awk '{print $3}')
[ -n "$WANT" ] || WANT="$FW_COMMIT"
log "framework commit $WANT"

if [ ! -d "$SRC/framework/scripts/mbedtls_framework" ]; then
    log "fetching the framework repository at $WANT"
    # ⛔ THE FRAMEWORK IS PINNED BY COMMIT AND THE CLONE IS ATOMIC, FOR THE SAME
    # REASON AS mbedTLS ITSELF. Three targets building at once each need it, and
    # the first version of this cloned into a shared path, so two of them
    # collided and the third reported:
    #
    #   fatal: fetch-pack: invalid index-pack output
    #
    # which names git's internals and not two builds sharing a directory.
    FW="$WORK/framework"
    clone_atomic https://github.com/Mbed-TLS/mbedtls-framework "$WANT" "$FW" \
        || die "cannot fetch mbedtls-framework at $WANT"
    # It is installed into the mbedtls tree, so the copy is atomic too: a build
    # that found a half-copied framework would fail in cmake with a Python
    # ModuleNotFoundError that says nothing about a concurrent copy.
    # ⛔ THE STAGING DIRECTORY IS OUTSIDE $SRC, NOT INSIDE IT. It was
    # $SRC/framework.tmp, and another target's build reaches `rm -rf "$SRC"`
    # during its own checkout, which deleted the staging directory mid-copy:
    #
    #   cp: preserving times for '.../framework.tmp': No such file or directory
    #
    # A staging path under a path another build deletes is not a staging path.
    STAGE="$WORK/.framework-stage.$$"
    rm -rf "$STAGE"
    cp -a "$FW" "$STAGE" || { rm -rf "$STAGE"; die "cannot stage the framework"; }
    rm -rf "$SRC/framework"
    mv "$STAGE" "$SRC/framework"
fi

# ------------------------------------------------------------------ configure
BUILD="$WORK/build-$TARGET"
rm -rf "$BUILD"
mkdir -p "$BUILD" || die "cannot create $BUILD"

# ⛔ THE COMPILER WRAPPER CARRIES THE TARGET EXPLICITLY. cmake probes the
# compiler with an empty source file and reads the target out of its output; a
# bare `zig cc` answers with the host triple and cmake then builds a host
# library that the cross dropssh would link by mistake. The wrapper is a script
# because cmake needs a single executable to call.
CC_WRAP="$BUILD/zigcc-$TARGET"
cat >"$CC_WRAP" <<WRAP
#!/bin/sh
exec zig cc -target $TARGET "\$@"
WRAP
chmod +x "$CC_WRAP" || die "cannot write the compiler wrapper"

log "configuring for $TARGET"
( cd "$BUILD" && \
  PYTHONPATH="$SRC/framework/scripts" \
  CC="$CC_WRAP" cmake "$SRC" \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_TESTING=OFF \
    -DENABLE_PROGRAMS=OFF \
    -DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
    -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    >cmake.log 2>&1 ) || { tail -20 "$BUILD/cmake.log" >&2; die "cmake failed"; }

log "compiling"
( cd "$BUILD" && make -j"$(nproc 2>/dev/null || echo 2)" install >make.log 2>&1 ) \
    || { tail -20 "$BUILD/make.log" >&2; die "make failed"; }

[ -f "$PREFIX/lib/libmbedtls.a" ] || die "libmbedtls.a is missing after the build"
log "installed to $PREFIX"
exit 0
