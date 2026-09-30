#!/bin/sh
# passwd-file-test.sh - a full login through a dropbear that has NO LD_PRELOAD.
#
# ⛔ THIS IS R9, AND IT IS THE WHOLE CLAIM IN ONE RUN. `dropssh relay` needs a
# passwd database in the cage and got one from an LD_PRELOAD shim, which is why
# the server half of a release is dynamic glibc while the client half is static
# musl, and why a musl dropbear cannot be built here at all. `dropbear -Y FILE`
# reads the database from a file instead, which removes the shim and with it the
# libc split.
#
# ⛔ AND THE ASSERTION IS THE ONLY ONE THAT MATTERS: the server's environment has
# NO LD_PRELOAD IN IT -- not unset, ABSENT -- and a real ssh client still gets in.
# A server that merely starts is not the claim; a server that AUTHENTICATES with
# no shim is, and a login that silently used the host's database would pass
# every weaker version of this.
#
# ⛔ WHY THIS IS A SHELL SCRIPT AND NOT PYTHON.
# ssh(1) takes `ProxyCommand` as a STRING and hands it to /bin/sh -c. Passing
# that string as one element of a Python argv list looks equivalent and is not:
# ssh then re-splits it, `sh` takes `/tmp/dr9` as the command name, and the
# error is "Permission denied" naming a DIRECTORY. The e2e works because it is
# a shell script, where the shell consumes the quotes before ssh ever sees the
# string. The first three versions of this were Python and all three failed
# with a message that named the wrong thing entirely.
#
# ⛔ AND THE CLIENT IS GIVEN THE SHIM WHILE THE SERVER IS NOT, BECAUSE THEY ARE
# DIFFERENT MACHINES IN THE SAME TEST. ssh(1) on a host with no /etc/passwd
# cannot map its OWN uid and refuses to start, so the CLIENT gets the shim to
# exist at all; the SERVER under test does not, because that is the claim.
# Conflating them is how the first version of this looked like an R9 failure
# for twenty minutes: the message was "No user exists for uid 0", which is
# OpenSSH complaining about the client, and it named the wrong process.
set -u

D="$1"
W="$2"
SHIM="$3"

hostkey="$W/r9-hk"
akdir="$W/r9-ak"
passwd="$W/r9-passwd"
sock="$W/r9.sock"

mkdir -p "$akdir"
rm -f "$hostkey" "$sock"

# The file names the current uid and comes before keygen: the shim REPLACES
# the passwd database, so a root-only file on a host that has a real one
# hides the user ssh-keygen runs as (CI runs as uid 1001). The login user is
# the current user for the same reason dropbear demands: login uid must equal
# the server's.
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
ME_HOME="$W/home"
mkdir -p "$ME_HOME"
# The home must be owned by the login user: dropbear refuses a login whose
# home is owned by someone else and writable ("must be owned by user or
# root"). /tmp fails that check for any non-root login.
printf '%s:x:%s:%s:test:%s:/bin/sh\n' "$ME_NAME" "$ME_UID" "$ME_GID" "$ME_HOME" >"$passwd"

export SANDHOME_PASSWD="$passwd"
LD_PRELOAD="$SHIM" ssh-keygen -q -t ed25519 -N '' -f "$akdir/id" 2>/dev/null
# ⛔ `dropbear -D DIR` looks for the authorized_keys FILE in DIR, not for a
# key named id there. The first version wrote id and id.pub and then reported
# "Permission denied (publickey)" from a server that had never been offered the
# key -- a real and correct message about a test that had not done its job.
cp "$akdir/id.pub" "$akdir/authorized_keys"
chmod 600 "$akdir/authorized_keys"
LD_PRELOAD="$SHIM" "$D/dropbearkey" -t ed25519 -f "$hostkey" >/dev/null 2>&1
cp "$akdir/id.pub" "$akdir/authorized_keys"

"$D/dropssh" relay --listen "unix://$sock" >"$W/r9-relay.log" 2>&1 &
relay_pid=$!
i=0
while [ $i -lt 200 ]; do [ -S "$sock" ] && break; sleep 0.05; i=$((i+1)); done

# ⛔ THE SERVER'S ENVIRONMENT HAS NO SHIM AT ALL. Not unset -- ABSENT, because
# that is what an operator who deleted fakepwd.so has, and "unset but the
# variable is still there" is a different thing.
env -u LD_PRELOAD -u SANDHOME_PASSWD \
    "$D/dropssh" serve --relay "unix://$sock" --name r9box --retry-budget 3 \
    --server "$D/dropbear -i -E -F -r $hostkey -D $akdir -Y $passwd" \
    >"$W/r9-serve.log" 2>&1 &
serve_pid=$!
sleep 2.5

LD_PRELOAD="$SHIM" SANDHOME_PASSWD="$passwd" timeout 40 ssh \
    -o "ProxyCommand=$D/dropssh connect --relay unix://$sock --name r9box" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=VERBOSE \
    -i "$akdir/id" "$ME_NAME@r9box" 'echo R9-LOGIN-OK' \
    >"$W/r9.out" 2>"$W/r9.err"
rc=$?

kill $serve_pid $relay_pid 2>/dev/null
wait $serve_pid $relay_pid 2>/dev/null

echo "ssh rc=$rc"
echo "stdout: $(cat "$W/r9.out" 2>/dev/null)"
echo "---- client stderr (VERBOSE: offered keys, proxy fate):"
cat "$W/r9.err" 2>/dev/null
echo "---- the key the client offered:"
LD_PRELOAD="$SHIM" SANDHOME_PASSWD="$passwd" ssh-keygen -y -f "$akdir/id" 2>&1 | head -c 120
echo
echo "---- serve log, in full (the server names its reason):"
cat "$W/r9-serve.log" 2>/dev/null
echo "---- akdir:"
ls -la "$akdir" 2>/dev/null
echo "---- passwd entry:"
cat "$passwd" 2>/dev/null
echo "---- who runs this:"
id 2>&1
echo "---- every component of the ak path (dropbear walks them all):"
if command -v namei >/dev/null 2>&1; then
    namei -l "$akdir/authorized_keys" 2>&1
else
    p="$akdir/authorized_keys"
    while [ "$p" != "/" ] && [ -n "$p" ]; do
        stat -c '%a %u:%g %n' "$p" 2>&1
        p=$(dirname "$p")
    done
    stat -c '%a %u:%g %n' / 2>&1
fi
if [ "$rc" = 0 ] && grep -qx R9-LOGIN-OK "$W/r9.out" 2>/dev/null; then
    echo "R9: a server with NO LD_PRELOAD in its environment authenticated a real ssh client"
    exit 0
fi
echo "R9: NOT ESTABLISHED"
exit 1
