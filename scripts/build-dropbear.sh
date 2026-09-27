#!/usr/bin/env bash
# build-dropbear.sh - the ssh server a cage can actually run, patched, for a
# target, with the passwd shim beside it.
#
# ⛔ WHY dropbear AND NOT sshd. Measured in the reference cage, in order:
#
#   1. `sshd -i -t -f <config>`  exits 0
#   2. `sshd -i` at runtime      "Privilege separation user nobody does not exist"
#   3. with a `nobody` entry     "Missing privilege separation directory:
#                                /var/chroot/ssh"  (and /var does not exist)
#   4. ChrootDirectory moved     no effect, a different hardcoded path
#   5. UsePrivilegeSeparation no deprecated and IGNORED since OpenSSH 8.4
#
# So no configuration makes a modern sshd run where chroot(2) is denied, and
# the default that picks it fails with an error from the FAR END, which reads
# as a dropssh bug. dropbear has no privsep chroot. The full measurement is in
# docs/decisions-tls.md.
#
# ⛔ AND IT IS BUILT DYNAMICALLY, WHICH IS THE PART THAT IS EASY TO GET WRONG
# AND IS INVISIBLE. A STATIC dropbear carries its own libc, so LD_PRELOAD
# cannot reach it, its passwd lookups fail against a cage with no /etc/passwd,
# and it logs "Login attempt for nonexistent user" for root, which is there.
# Measured here, same patched source, built both ways, through a real session:
#
#   dynamic, no shim     Login attempt for nonexistent user from localhost
#   dynamic, +shim       User 'root' has invalid shell, rejected   (shell)
#   dynamic, +shim+passwd Pubkey auth succeeded, uid 0, exit 0
#
# The build asserts the artefact is dynamic. The flag is the `STATIC=` value
# that dropbear's configure computes, and passing an unknown
# `--disable-static-programs` to it is a no-op that autoconf warns about but
# does not fail on, which is exactly the kind of thing that leaves you with a
# static binary and no error. The assertion below is the real guard.
#
# USAGE: build-dropbear.sh TARGET OUTDIR [COMMIT]
set -uo pipefail

TARGET="${1:?target required}"
OUTDIR="${2:?outdir required}"
COMMIT="${3:-59870ad43153fe8d4f1c96f5d5752116c94f31ff}"

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
WORK="${DROPBEAR_WORK:-$ROOT/.deps/dropbear/$TARGET}"

log() { printf '[dropbear %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FAIL: $*"; exit 1; }

command -v git >/dev/null 2>&1 || die "git is required"
command -v make >/dev/null 2>&1 || die "make is required"
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"

# ------------------------------------------------------------------ source
if [ ! -f "$WORK/src/svr-auth.c" ]; then
    log "fetching dropbear $COMMIT"
    rm -rf "$WORK"
    mkdir -p "$WORK" || die "cannot create $WORK"
    # A COMMIT, not a version string. The version lives in the source
    # (src/sysoptions.h), not in a ref, so `git clone --branch 2026.94` fails
    # with "Remote branch not found". A commit always resolves, and it is what
    # a published artefact with a patch in it must be pinned to.
    git -C "$WORK" init -q || die "cannot init $WORK"
    git -C "$WORK" remote add origin https://github.com/mkj/dropbear 2>/dev/null || true
    git -C "$WORK" fetch -q --depth 1 origin "$COMMIT" || die "cannot fetch dropbear $COMMIT"
    git -C "$WORK" checkout -q FETCH_HEAD || die "cannot check out $COMMIT"
fi
ACTUAL=$(git -C "$WORK" rev-parse HEAD 2>/dev/null || echo unknown)
log "source $WORK at $ACTUAL"
VER=$(sed -n 's/.*#define DROPBEAR_VERSION "\([^"]*\)".*/\1/p' "$WORK/src/sysoptions.h")
log "dropbear version $VER"

# ------------------------------------------------------------------ patches
# Each patch is idempotent and says so when it is already applied. A patch
# that upstream has already taken must not be re-applied; a patch that fails to
# apply must stop the build rather than produce a server that silently lacks it.
apply_patch() {
    local name="$1" file="$2" marker="$3"
    if grep -q "$marker" "$WORK/$file" 2>/dev/null; then
        log "  $name: already present"
        return 0
    fi
    if git -C "$WORK" apply --check "$HERE/../patches/$name" 2>/dev/null; then
        git -C "$WORK" apply "$HERE/../patches/$name" || die "$name did not apply"
        log "  $name: applied"
    else
        die "$name does not apply to $ACTUAL; refusing to ship a server without it"
    fi
}

# ⛔ setgroups(2) IS DENIED BY A SECCOMP CAGE, AND initgroups() THEREFORE
# ALWAYS FAILS, so a server that treats it as fatal cannot log anyone in. This
# is not theoretical: the log line is "Error changing user group" on every
# login. setgid STAYS FATAL, because setgid is the call that changes the group
# and its failure is a real privilege problem; a denied initgroups leaves a
# session with the right uid and gid and no supplementary groups.
apply_patch dropbear-setgroups-tolerance.patch src/svr-auth.c "Sandboxed hosts"

# The login-shell check. /etc/shells is a policy for a multi-user system, and a
# host that HAS one listing only bash refuses a passwd entry naming /bin/sh.
# Measured on a GitHub Actions runner, 2026-09-27:
#
#   Login attempt with wrong user root from localhost:...
#   Exit before auth from <localhost:...>: (user 'root', 0 fails)
#
# with the user present, the shell present and the shell executable. The same
# binary on a host with no /etc/shells works, because dropbear then uses a
# compiled-in fallback list. So the failure depends on whether a POLICY FILE
# exists, which is the opposite of what a cage wants. The patch consults the
# list first, so a host with a policy keeps it, and accepts an executable shell
# when the list does not name one.
if grep -q "is not in the list but is executable" "$WORK/src/svr-auth.c" 2>/dev/null; then
    log "  login shell tolerance: already in this commit"
else
    apply_patch dropbear-login-shell-tolerance.patch src/svr-auth.c "is not in the list but is executable"
fi

# ENOTSOCK: a server carried on a pipe has no peer address to log. The current
# pin already carries this upstream, so this is asserted rather than patched,
# and the build says which of the two happened.
if grep -q "ENOTSOCK\|Peer socket" "$WORK/src/netio.c" 2>/dev/null; then
    log "  inetd pipe tolerance: already in this commit"
else
    apply_patch dropbear-inetd-pipe-tolerance.patch src/netio.c "ENOTSOCK"
fi

# ------------------------------------------------------------------ configure
# ⚠ STATIC IS THE ONLY LEVER THAT MATTERS AND IT IS A CONFIGURE VALUE.
# `--disable-static-programs` is NOT an option this configure knows; it warns
# "unrecognized options" and carries on. The check that matters is the
# artefact's linkage, asserted below.
# ⚠ ON A MUSL TARGET THE LINK MUST BE EXPLICITLY DYNAMIC, OR THE RESULT IS A
# static-pie BINARY THAT LOOKS DYNAMIC AND CANNOT BE PRELOADED.
#
# Measured here: `zig cc -target x86_64-linux-musl` with no -static still
# produces a "static-pie linked" executable, which `file` reports as neither
# plainly static nor plainly dynamic and which LD_PRELOAD cannot reach. So a
# dropbear built that way passes a casual linkage check and fails every login
# in a cage with the message that names the wrong thing. The check below does
# not accept "static-pie".
# ⛔ THE DYNAMIC LOADER IS NAMED PER TARGET, AND A TARGET WITH NO ENTRY HERE IS
# A BUILD FAILURE RATHER THAN A SILENT STATIC-PIE.
#
# Measured in CI, 2026-09-27, on riscv64-linux-gnu and powerpc64le-linux-musl:
#
#   configure: error: C compiler cannot create executables
#
# which names the compiler and not the missing `--dynamic-linker`. Without one
# zig cc emits a static-pie binary, and static-pie is exactly the case that
# looks fine and fails every login in a cage, because LD_PRELOAD cannot reach
# it. So an unknown target is refused here, where the message can say what is
# missing, rather than at the operator's machine, where it cannot.
DL=""
DL_KNOWN=1
case "$TARGET" in
    x86_64-linux-musl)      DL="/lib/ld-musl-x86_64.so.1" ;;
    aarch64-linux-musl)     DL="/lib/ld-musl-aarch64.so.1" ;;
    arm-linux-musleabihf)   DL="/lib/ld-musl-armhf.so.1" ;;
    arm-linux-musleabi)     DL="/lib/ld-musl-arm.so.1" ;;
    x86-linux-musl)         DL="/lib/ld-musl-i386.so.1" ;;
    i386-linux-musl)        DL="/lib/ld-musl-i386.so.1" ;;
    riscv64-linux-musl)     DL="/lib/ld-musl-riscv64.so.1" ;;
    powerpc64le-linux-musl) DL="/lib/ld-musl-powerpc64le.so.1" ;;
    x86_64-linux-gnu)      DL="/lib64/ld-linux-x86-64.so.2" ;;
    aarch64-linux-gnu)     DL="/lib/ld-linux-aarch64.so.1" ;;
    arm-linux-gnueabihf)    DL="/lib/ld-linux-armhf.so.3" ;;
    riscv64-linux-gnu)      DL="/lib/ld-linux-riscv64-lp64d.so.1" ;;
    powerpc64le-linux-gnu)  DL="/lib64/ld64.so.2" ;;
    *)
        DL_KNOWN=0
        ;;
esac
if [ "$DL_KNOWN" -eq 0 ]; then
    die "no dynamic loader is known for $TARGET.
       A dropbear built without one is static-pie, and LD_PRELOAD cannot reach
       static-pie, so every login in a cage would say 'nonexistent user' for a
       user that is there. Add the target's loader path to the DL case above,
       or pass DROPBEAR_SKIP_LINKER_CHECK=1 if you have verified the toolchain
       produces a dynamic binary without one."
fi
if [ -n "${DROPBEAR_SKIP_LINKER_CHECK:-}" ]; then
    DL=""
fi
# ⛔ `-rdynamic`, AND NOT `-pie`, IS WHAT MAKES A musl BINARY DYNAMICALLY LINKED
# UNDER zig cc. Measured on this host, same source, same target:
#
#   zig cc -target riscv64-linux-musl -pie ...   -> "pie executable ... static-pie"
#   zig cc -target riscv64-linux-musl -rdynamic  -> "LSB executable" (dynamic)
#
# `-pie` is what dropbear's own Makefile adds (LDFLAGS ends in -pie), and on a
# glibc target that is right. On a musl target zig's linker resolves it to a
# static-pie, which is the exact artefact the shim cannot preload. `-rdynamic`
# keeps the dynamic loader, so the shim reaches it.
#
# The flag is appended after the Makefile's own LDFLAGS so it wins, and the
# artefact is checked afterwards either way, because a flag that produces the
# right thing is a convenience and a check is a guarantee.
# ⛔ A musl dropbear IS NOT BUILDABLE WITH zig cc, AND THE REASON IS MEASURED,
# SO THE BUILD REFUSES IT HERE RATHER THAN SHIPPING static-pie.
#
#   zig cc -target riscv64-linux-musl -rdynamic -c x.c
#     ld.lld: error: -r and --export-dynamic may not be used together
#
# `-rdynamic` is the only flag that yields a dynamically linked musl binary
# (`-pie` gives static-pie, which the shim cannot preload), and it fails on the
# relocatable link that autoconf's "cannot compute suffix of object files" probe
# performs. The same source with `-pie` compiles and links, and produces exactly
# the artefact this build exists to refuse.
#
# So the two sides of this project have different libc requirements, and they
# are not negotiable: dropssh must be musl to run in a cage, and dropbear must
# be glibc to be preloaded. A musl dropbear is refused, with this, rather than
# produced and found broken at login.
case "$TARGET" in
    *-linux-musl)
        die "a musl dropbear cannot be built: zig cc has no flag that yields a
       dynamically linked musl binary AND survives autoconf's -c probe.
       -pie gives static-pie, which LD_PRELOAD cannot reach; -rdynamic gives a
       dynamic binary but fails the -c probe with '-r and --export-dynamic may
       not be used together'. Build the server for a glibc target
       (--dropbear-target x86_64-linux-gnu) and the dropssh side for this one.
       See docs/decisions-tls.md."
        ;;
esac

CC_WRAP="$WORK/zigcc-$TARGET"
if [ -n "$DL" ]; then
    cat >"$CC_WRAP" <<WRAP
#!/bin/sh
exec zig cc -target $TARGET -pie -Wl,--dynamic-linker=$DL "\$@"
WRAP
else
    cat >"$CC_WRAP" <<WRAP
#!/bin/sh
exec zig cc -target $TARGET -pie "\$@"
WRAP
fi
chmod +x "$CC_WRAP"

# ⛔ PASSWORD AUTH IS OFF, AND IT IS OFF BECAUSE A CAGE HAS NO PASSWORD
# DATABASE, NOT TO SAVE A FEW KILOBYTES.
#
# dropbear's sysoptions.h makes DROPBEAR_SVR_PASSWORD_AUTH depend on crypt(3),
# and a statically-linked-musl cross build has no crypt(), so the build dies
# with:
#
#   #error "DROPBEAR_SVR_PASSWORD_AUTH requires `crypt()'."
#
# Turning it off is also the right server for this tool: authentication is
# public key only, the authorized_keys file is the credential, and there is no
# /etc/shadow for a password to be checked against even if crypt() existed. A
# server that offers password auth in a cage invites an operator to try a
# password, and the failure of that is a confusing auth failure rather than a
# clear "this server does not do passwords".
log "editing localoptions.h: pubkey-only server"
cat >"$WORK/localoptions.h" <<'LOCAL'
/* dropssh server options. See docs/decisions-tls.md for why each is here. */

/* ⛔ THESE ARE #define'd TO 0 AND NOT #undef'd, AND THE ORDER IS THE WHOLE
 * REASON. src/options.h includes localoptions.h at line 21 and sysoptions.h at
 * line 29, and sysoptions.h holds the #error. An #undef here runs before the
 * option is ever defined and is undone by default_options_guard.h at line 25,
 * which is `#ifndef`-wrapped, so the build dies with
 *
 *   #error "DROPBEAR_SVR_PASSWORD_AUTH requires `crypt()'."
 *
 * naming crypt() and saying nothing about a header being read at the wrong
 * time. Three hours of guessing at crypt() would not have found it; reading
 * the include order did.
 *
 * Public key only: a cage has no /etc/shadow, and crypt() is absent from the
 * cross toolchain. Offering password auth invites an operator to try a
 * password and get a confusing failure instead of a clear refusal. */
#define DROPBEAR_SVR_PASSWORD_AUTH 0
#define DROPBEAR_SVR_PAM_AUTH 0

/* No client: this is a server artefact and the operator's ssh is OpenSSH. */
#define DROPBEAR_CLI 0
LOCAL

log "configure (dynamic on purpose)"
# ⛔ _FORTIFY_SOURCE IS TURNED OFF, AND THE REASON IS A LINK ERROR THAT NAMES
# A SYMBOL NOBODY ASKED FOR.
#
# zig cc enables _FORTIFY_SOURCE by default at -O2 on a glibc target, and
# glibc's fortify wrappers call __strlcpy_chk. A musl target has no such
# wrapper, so the link fails with:
#
#   ld.lld: error: undefined symbol: __strlcpy_chk
#   >>> referenced by dbutil.c ... did you mean: __strncpy_chk
#
# which names a hardening macro, not a missing library, and sends you looking
# for a libc that has it. The fix is to not ask for the macro:
# -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0.
#
# This does not weaken the build in the way it appears to. The fortified
# wrappers are a glibc feature; on a musl target there is nothing to weaken,
# and the buffer sizes here are all compile-time constants that the compiler
# checks without the macro.
CFLAGS_EXTRA="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"
# ⛔ --host IS PASSED FOR A CROSS BUILD, AND AUTOCONF'S ERROR NAMES THE FLAG.
#
#   configure: error: cannot run C compiled programs.
#   If you meant to cross compile, use `--host'.
#
# For the host target it is `--build`; for any other it is `--host=<arch>-pc`.
# Without it, autoconf tries to EXECUTE what it compiled to test it, which
# fails on any foreign architecture, and the first version of this script
# therefore worked only for the build machine's own arch.
HOST_TRIPLE=""
case "$TARGET" in
    x86_64-linux-gnu)   HOST_TRIPLE="x86_64-pc-linux-gnu" ;;
    aarch64-linux-gnu)  HOST_TRIPLE="aarch64-pc-linux-gnu" ;;
    arm-linux-gnueabihf) HOST_TRIPLE="arm-unknown-linux-gnueabihf" ;;
    x86_64-linux-musl)  HOST_TRIPLE="x86_64-pc-linux-musl" ;;
    aarch64-linux-musl) HOST_TRIPLE="aarch64-pc-linux-musl" ;;
    x86-linux-musl)     HOST_TRIPLE="i686-pc-linux-musl" ;;
    riscv64-linux-musl) HOST_TRIPLE="riscv64-unknown-linux-musl" ;;
    powerpc64le-linux-musl) HOST_TRIPLE="powerpc64le-unknown-linux-musl" ;;
    riscv64-linux-gnu)  HOST_TRIPLE="riscv64-unknown-linux-gnu" ;;
    powerpc64le-linux-gnu) HOST_TRIPLE="powerpc64le-unknown-linux-gnu" ;;
esac
CONFIGURE_HOST=""
[ -n "$HOST_TRIPLE" ] && CONFIGURE_HOST="--host=$HOST_TRIPLE"
( cd "$WORK" && CC="$CC_WRAP" CFLAGS="$CFLAGS_EXTRA" \
  ./configure --disable-zlib --disable-usage $CONFIGURE_HOST \
      --prefix="$WORK/inst" >configure.log 2>&1 ) \
    || { tail -20 "$WORK/configure.log" >&2; die "configure failed"; }

# ⛔ STATIC IS FORCED OFF HERE, EXPLICITLY, AND THE RESULT IS CHECKED AFTERWARDS.
# dropbear's configure sets STATIC=1 when it decides a static link is possible.
# In a cross build with zig cc that decision is made from the WRONG compiler's
# answer, so the build passes STATIC=0 to make() and then checks the artefact.
sed -i 's/^STATIC=.*/STATIC=0/' "$WORK/Makefile" 2>/dev/null || true
grep -q '^STATIC=0' "$WORK/Makefile" || die "could not force STATIC=0 in the Makefile"

log "make"
( cd "$WORK" && make -j"$(nproc 2>/dev/null || echo 2)" dropbear dropbearkey \
    >make.log 2>&1 ) || { tail -30 "$WORK/make.log" >&2; die "make failed"; }

[ -x "$WORK/dropbear" ]    || die "no dropbear binary at $WORK/dropbear"
[ -x "$WORK/dropbearkey" ] || die "no dropbearkey at $WORK/dropbearkey"

# ------------------------------------------------------------------ checks
fail=0
note() { log "  $1"; }
bad()  { log "  FAIL: $1"; fail=1; }

# ⛔ THE LINKAGE IS THE PROPERTY THAT FAILS SILENTLY. Everything else about
# the build can be green while the server cannot log anyone in, because the
# failure appears at LOGIN, on someone else's machine, as a message that names
# the wrong thing. So it is checked here, on the artefact, before it ships.
if command -v file >/dev/null 2>&1; then
    KIND=$(file -b "$WORK/dropbear")
    case "$KIND" in
        *"statically linked"*|*"static-pie linked"*)
            bad "dropbear is STATIC (or static-pie): LD_PRELOAD cannot reach
                 either, so the passwd shim is dead and every login says
                 'nonexistent user' for a user that is there. $KIND" ;;
        *"dynamically linked"*) note "dynamic, as the shim requires" ;;
        *) note "could not classify: $KIND" ;;
    esac
fi

# The setgid exit string must still be in the binary: its PRESENCE is correct
# (setgid stays fatal) and its ABSENCE is the defect. The first version of this
# check read it the other way round and failed a good build, which is what an
# assertion written from a guess looks like.
if command -v strings >/dev/null 2>&1; then
    # ⛔ `grep -c`, NOT `grep -q`, UNDER pipefail. `grep -q` exits on the first
    # match, `strings` takes a SIGPIPE, and the PIPELINE reports 141, which
    # under `set -o pipefail` reads as "the string is absent" for a string that
    # is present. Measured: MATCH without pipefail, NOMATCH with it.
    if [ "$(strings "$WORK/dropbear" 2>/dev/null | grep -c 'Error changing user group')" -ge 1 ]; then
        note "setgid stays fatal, as intended: the exit string is in the binary"
    else
        bad "the setgid exit string is gone, so the tolerance took setgid with it"
    fi
fi

# ⛔ THE TOLERANCE IS CHECKED IN THE SOURCE, AND THE SEARCH IS BOUNDED TO THE
# BLOCK. "The compiled form of this initgroups failure is ignored" is the
# ABSENCE of a dropbear_exit, which no string search can see. An `awk` with a
# sticky flag scans to end-of-file and finds a dropbear_exit belonging to a
# different failure thirty lines later, which makes a correct patch look
# unlanded. So the block is matched as a unit.
if python3 - "$WORK/src/svr-auth.c" <<'PYEOF2'
import re, sys
s = open(sys.argv[1]).read()
# The invariant is not "initgroups has no dropbear_exit in it". The patch
# keeps ONE, and deliberately: a denied setgroups(2) is tolerated only when
# the process's gid already equals the gid the session wants, so a real
# failure to change group is still fatal. The first version of this check
# asserted no dropbear_exit anywhere in the block and failed a correct
# patch, which is what an assertion written from a summary looks like.
#
# What is actually checked:
#   1. the initgroups condition exists and is bounded (a sticky-flag scan to
#      end-of-file finds a dropbear_exit belonging to something else),
#   2. the exit inside it is guarded by a gid comparison, so a real group
#      change that fails is still fatal,
#   3. the tolerance is explained, so a later reader knows it is deliberate.
m = re.search(r"if \(initgroups\(.*?\)\s*<\s*0\)\s*\{(.*?)\n\t\t\}", s, re.S)
if not m:
    sys.stderr.write("no initgroups condition found\n"); sys.exit(2)
body = m.group(1)
if "dropbear_exit" not in body:
    sys.stderr.write("initgroups failure is ignored unconditionally; a real "
                     "gid change that fails would be silent\n"); sys.exit(1)
if "getgid()" not in body:
    sys.stderr.write("the initgroups exit is not guarded by a gid check, so "
                     "the tolerance is broader than it should be\n"); sys.exit(1)
if "Sandboxed hosts" not in body and "Intentionally ignored" not in body:
    sys.stderr.write("the tolerance is not explained in the block\n"); sys.exit(1)
sys.exit(0)
PYEOF2
then note "initgroups failure is tolerated, and only where the gid is unchanged"
else bad "the initgroups tolerance is missing, or is broader than it should be"
fi

# ------------------------------------------------------------------ shim
# ⛔ THE SHIM IS A BUILD OUTPUT AND IS NEVER COMMITTED. It is built here, for
# the same libc as the server it is meant to preload, and it ships beside the
# server. A release with a server and no shim is the one combination that
# cannot work in a cage, and the failure is at login on someone else's machine.
# ⛔ THE SHIM COMES FROM sandhome, PINNED, AND IS NOT VENDORED HERE.
#
# The passwd shim used to live in two places: this tree and sandssh, and the
# copies drifted. It now lives in talaria0101/sandhome, which is also where
# errandsh and the isatty shim live, and dropssh fetches the one file it needs
# at build time. Two copies of a shim is how a cage ends up with a shim that
# reads a variable name nothing sets.
#
# The pin is a commit, so a build is reproducible. It can be overridden with
# SANDHOME_REF for a local checkout, which is what a developer wants.
SANDHOME_REF="${SANDHOME_REF:-5a103da}"
SANDHOME_DIR="${SANDHOME_DIR:-$ROOT/.deps/sandhome}"
SHIM="$SANDHOME_DIR/shims/fakepwd.c"
if [ ! -f "$SHIM" ]; then
    log "fetching the passwd shim from sandhome@$SANDHOME_REF"
    if [ -d "$SANDHOME_DIR/.git" ]; then
        git -C "$SANDHOME_DIR" fetch -q --depth 1 origin "$SANDHOME_REF" \
            || die "cannot fetch sandhome $SANDHOME_REF"
        git -C "$SANDHOME_DIR" checkout -q FETCH_HEAD \
            || die "cannot check out sandhome $SANDHOME_REF"
    else
        rm -rf "$SANDHOME_DIR"
        git clone -q --depth 1 https://github.com/talaria0101/sandhome "$SANDHOME_DIR" \
            || die "cannot clone sandhome"
        git -C "$SANDHOME_DIR" checkout -q "$SANDHOME_REF" 2>/dev/null || true
    fi
fi
[ -f "$SHIM" ] || die "no shims/fakepwd.c in sandhome at $SANDHOME_DIR"
CC_WRAP2="$WORK/zigcc-shared-$TARGET"
cat >"$CC_WRAP2" <<WRAP
#!/bin/sh
exec zig cc -target $TARGET -shared -fPIC "\$@"
WRAP
chmod +x "$CC_WRAP2"
"$CC_WRAP2" -O2 -o "$OUTDIR/fakepwd.so" "$SHIM" 2>"$OUTDIR/fakepwd.build.log" \
    || { cat "$OUTDIR/fakepwd.build.log" >&2; die "the passwd shim did not build"; }
[ -f "$OUTDIR/fakepwd.so" ] || die "no fakepwd.so after the build"
note "passwd shim built for this target"

# The version goes into the artefact so BUILDINFO can report what was actually
# built, read from the tree the build fetched rather than from a constant here.
printf 'version %s\ncommit %s\n' "$VER" "$ACTUAL" > "$OUTDIR/VERSION"
note "version $VER recorded from the fetched tree"

# ------------------------------------------------------------------ publish
cp "$WORK/dropbear" "$OUTDIR/dropbear"    || die "cannot copy dropbear"
cp "$WORK/dropbearkey" "$OUTDIR/dropbearkey" || die "cannot copy dropbearkey"
chmod 0755 "$OUTDIR/dropbear" "$OUTDIR/dropbearkey"

# A passwd file that names a shell which exists, because the shim's built-in
# default is /bin/bash and a cage often has only /bin/sh. Shipping it means the
# one-line start command in the README works without the operator having to
# know that.
#
# The name is SANDHOME_PASSWD, which is what sandhome's shim reads first. It
# also still reads SANDHOME_PASSWD for machines configured against the old
# name, so this is a rename rather than a break.
cat >"$OUTDIR/passwd" <<'PW'
root:x:0:0:root:/root:/bin/sh
PW
note "passwd file written (shell=/bin/sh)"

[ "$fail" -eq 0 ] || { log "dropbear checks FAILED"; exit 1; }
log "dropbear $VER at $ACTUAL is ready in $OUTDIR"
exit 0
