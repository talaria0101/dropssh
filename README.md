# dropssh

**dropbear, with a relay built in, so a sealed cage can be ssh'd into.**

A cage with no pty, no `/etc/passwd`, no chroot, no `/var`, no resolver, and
only HTTPS:443 egress is reachable from the outside by nobody, because it has
no port to be reached on. `dropssh` is the answer to that: it dials **out** to a
relay, waits to be paired, and hands each session to a real `dropbear` on a
socketpair. No inbound port, no chroot, no privilege-separation user, no `/var`.

Two binaries, built for two libcs, on purpose:

| binary | libc | why |
| --- | --- | --- |
| `dropssh` | **static musl** | the one you download and run. A cage has no libc to link against. |
| `dropbear` | **dynamic glibc** | the passwd shim is an `LD_PRELOAD`, and musl's `RTLD_NEXT` resolves to `NULL` for a libc symbol, so a musl dropbear cannot be interposed at all. |

The full measurement behind that split is in
[`docs/decisions-tls.md`](docs/decisions-tls.md). It is the opposite of the
obvious guess, and getting it wrong ships a server that cannot log anyone in.

## Get a shell

On the machine you want into, with the release unpacked:

```sh
./dropbearkey -t ed25519 -f hostkey
mkdir -p ak && cp ~/.ssh/id_ed25519.pub ak/authorized_keys && chmod 600 ak/authorized_keys

./dropssh serve --name mycage \
    --passwd ./passwd --preload ./fakepwd.so \
    --server './dropbear -i -E -F -r hostkey -D ak'
```

`--passwd` and `--preload` are what make it work in a cage: the first supplies
the passwd database `dropbear` cannot find, the second is the shim that
intercepts the lookup. Without them dropbear logs `Login attempt for
nonexistent user` for `root`, which is there. Both the shim and the isatty
shim live in [`sandhome`](https://github.com/talaria0101/sandhome); the builder
fetches them pinned, so there is one copy of each and not a stale one here.

From your own machine:

```sh
ssh -o ProxyCommand='./dropssh connect --name mycage' -i ~/.ssh/id_ed25519 root@mycage
```

That is the whole thing. `dropssh connect` is an ssh `ProxyCommand`: it mints
its own relay token, opens the websocket, and carries the ssh bytes. No token
to obtain, no configuration to write, no `~/.ssh/config` stanza to get right.

## Reach a public ssh gateway through a relay

No node of your own, no config:

```sh
ssh -o ProxyCommand='./dropssh connect --mint' root@railway.new
```

`--mint` asks the relay for a token and sends it as a header. A forward token is
self-service; a reverse node token is not, and is only needed by `serve`.

## Run your own relay

```sh
./dropssh relay --listen unix:///tmp/dropssh.sock
```

A **rendezvous**: two peers both dial it and it pairs them. It is not a forward
proxy and cannot reach a target on a client's behalf; the two differ in exactly
which hop is last.

## Build

```sh
# --target is the dropssh binary, --dropbear-target is the server's
scripts/build.sh --target x86_64-linux-musl \
                 --dropbear-target x86_64-linux-gnu \
                 --out dist/x86_64-linux-musl
tests/e2e.sh dist/x86_64-linux-musl
```

`build.sh` fetches and pins mbedTLS and dropbear, applies the patches, builds
both binaries, and asserts the properties that fail silently. The e2e then
proves a real session runs through the artefact, because a binary that compiles
and cannot log anyone in is the failure this exists to prevent.

Supported `dropssh` targets, all six verified building here, in parallel from
one checkout: `x86_64-linux-musl`, `aarch64-linux-musl`, `arm-linux-musleabihf`,
`x86-linux-musl`, `riscv64-linux-musl`, `powerpc64le-linux-musl`.

Supported `dropbear` targets: `x86_64-linux-gnu`, `aarch64-linux-gnu`,
`arm-linux-gnueabihf`. The server is glibc because the shim needs `RTLD_NEXT`,
and a musl server cannot be built at all under `zig cc`; the reasoning and the
measurements are in [`docs/decisions-tls.md`](docs/decisions-tls.md). The
builder refuses a musl server target by name rather than producing one.

## What it does not do, and what is known broken

`dropssh serve` carries one session at a time and does not yet speak the
relay's multiplexed reverse protocol. Every open defect and every requested
feature is numbered in [`docs/relay-issues.md`](docs/relay-issues.md); B1 to B5
are the reverse path, and B4 is the root cause of most of the rest. The
server-side items are in [`docs/open-issues.md`](docs/open-issues.md).

The paths that are implemented are the **forward** relay and the
**rendezvous**, and both are proven with a real session.

- **No pty.** A cage has no `/dev/ptmx` and nothing in userspace can create
  one, so `ssh -t` is refused rather than silently degraded. A full-screen TUI
  cannot run; an interactive *line* can, and
  [`sandhome`](https://github.com/talaria0101/sandhome) ships `errandsh`, a
  POSIX sh line discipline for exactly that.
- **No UDP, no inbound.** The relay is HTTPS on 443 in both directions.
- **No password auth.** The server is public key only, which is also what a cage
  with no `/etc/shadow` can actually do.
