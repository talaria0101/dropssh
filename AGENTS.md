# AGENTS.md

**An agent working in this repository should read this and nothing else.** It is
self-contained: everything you need to build, test and extend dropssh is here or
in the files it names.

## What this is

`dropssh` makes a sealed cage reachable over ssh. A cage with no pty, no
`/etc/passwd`, no chroot, no `/var`, no resolver and only HTTPS:443 egress is
unreachable from outside **by construction**: it has no port to be reached on.
`dropssh` dials *out* to a relay, waits to be paired, and hands each session to
a real `dropbear` running on a socketpair. No inbound port, no chroot, no
privilege-separation user.

All of it is C. No python at runtime, nothing to install.

## The one command

```sh
# inside the cage
./dropbearkey -t ed25519 -f hostkey
mkdir -p ak && cp ~/.ssh/id_ed25519.pub ak/authorized_keys && chmod 600 ak/authorized_keys

./dropssh serve --name N --passwd ./passwd --preload ./fakepwd.so \
                --server './dropbear -i -E -F -r hostkey -D ak'

# from your own machine
ssh -o ProxyCommand='./dropssh connect --name N' root@N
```

`dropssh connect` is an ssh `ProxyCommand`. It mints its own relay token, so
there is nothing to obtain and no `~/.ssh/config` stanza to get right.

To reach a public ssh gateway through a relay, with no node of your own:

```sh
ssh -o ProxyCommand='./dropssh connect --mint' root@railway.new
```

## The two binaries, and why they are for different libcs

This is the first thing to understand and the easiest to get wrong.

| binary | libc | why |
| --- | --- | --- |
| `dropssh` | **static musl** | the one you download and run. A cage has no libc to link against. |
| `dropbear` | **dynamic glibc** | the passwd shim is an `LD_PRELOAD` and needs `RTLD_NEXT`, which musl resolves to `NULL` for a libc symbol, so a musl dropbear cannot be interposed at all. Not static, not static-pie, and not with `-rdynamic`. |

Getting that wrong ships a server that compiles, links, passes every static
check, and logs `Login attempt for nonexistent user` for `root`, which is
there. So it is asserted **on the artefact**, and `static-pie` is refused
alongside `static` because static-pie is the case that looks fine and fails
every login.

Full measurements: [`docs/decisions-tls.md`](docs/decisions-tls.md).

## Reading order

1. This file.
2. [`docs/decisions-tls.md`](docs/decisions-tls.md) — the libc split, the
   patches, and the six defects CI found that a cage could not.
3. [`docs/reverse-relay.md`](docs/reverse-relay.md) — the relay's reverse
   protocol, as measured live. **The two legs are not symmetric** and that is
   the thing to know first.
4. [`docs/multiplexing.md`](docs/multiplexing.md) — the eight framing defects
   found while attempting the multiplexed reverse path, and the shape that does
   not have them. **The path is implemented now**; this page is why it is not
   trivially so.
5. **[`docs/relay-issues.md`](docs/relay-issues.md) — every bug and every
   request concerning the relay, its protocol and the two verbs that speak to
   it, and what happened to each. Start here.**
6. [`README.md`](README.md) — usage and the full option list.

## Building

```sh
# --target is the dropssh binary, --dropbear-target is the server's.
# They are different on purpose; see above.
scripts/build.sh --target x86_64-linux-musl \
                 --dropbear-target x86_64-linux-gnu \
                 --out dist/x86_64-linux-musl
tests/e2e.sh dist/x86_64-linux-musl
```

`zig cc` compiles everything, so a cross build is a flag. mbedTLS, dropbear and
the sandhome shims are **fetched and pinned, not vendored**:

| input | pinned by | fetched by |
| --- | --- | --- |
| dropbear | `DROPBEAR_COMMIT`, a commit | `scripts/build-dropbear.sh` |
| mbedTLS | its tag | `scripts/build-mbedtls.sh` |
| the passwd and isatty shims | `SANDHOME_REF` | `scripts/build-dropbear.sh` |

dropbear is pinned by **commit** because its version lives in
`src/sysoptions.h` and not in a git ref, so a version string is not something
git can resolve.

**Supported targets**, all verified building in CI:

* `dropssh`, static musl: `x86_64`, `aarch64`, `armv7`, `x86-32`, `riscv64`,
  `powerpc64le`
* `dropbear`, dynamic glibc: `x86_64-gnu`, `aarch64-gnu`, `arm-gnueabihf`

## Testing

`tests/e2e.sh` is the gate, and it is not a smoke test. It carries real bytes
through a real `ssh` client, because **a binary that compiles and cannot log
anyone in is the failure this project exists to prevent**, and `dropbear -t`,
`file` and a green `make` are all incapable of seeing it: it appears at login,
on a machine with no `/etc/passwd`, as a message that names the wrong thing.

**Nineteen** cases, green on a CI runner at uid 1001 and in a cage at uid 0:

* dropbear is dynamically linked, so the shim can reach it
* `dropbear -i` stays up on a **socketpair** waiting for a session
* a pubkey session to uid 0, through relay, serve, dropbear and connect
* a 270 KB transfer that comes back byte for byte
* a session as the login user with the shipped passwd file
* a login with an executable shell is accepted
* a login with a shell that does **not** exist is refused, and says which shell
* connecting to a name no node is using exits non-zero
* the binary reports its TLS backend
* **two concurrent sessions on one node socket**, each receiving only its own
  bytes, and the node's own log showing one registration for two sessions
* the relay's framing rules (via `tests/mux-probe.py`): the id asymmetry, the
  1009 close for a bare node frame, the 1003 close for a text data frame
* `doctor` reports the environment and exits non-zero on a failed check
* `config` prints every setting with its source, and never a token's value
* `--json` produces a parseable event on stderr and leaves stdout clean

Two things about how to read it:

* **Every guard is proven to fire.** A check that has only ever passed is not
  evidence. Planting a static-pie dropbear turns the suite red on two checks,
  and CI has a job that asserts a musl dropbear is **refused**. The same rule
  was applied to the multiplexer: `tests/mux-probe.py` was rebuilt against a
  relay with the silent drop restored and against one with the id strip
  removed, and it failed both times.
* **The suite logs in as whatever uid it runs as**, and says so on the first
  line. dropbear refuses a login whose uid differs from the server's, so a
  suite that assumes it runs as root is a test of a different machine.

## Repository layout

```
src/            the C.
                transport.c  TCP, an HTTP CONNECT proxy that resolves names
                             itself, and unix sockets
                dns.c        getaddrinfo, then /etc/hosts, then DoH, cached
                ws.c         RFC 6455 framing, the relay handshake, token mint
                tls_mbed.c   mbedTLS, verification on by default
                serve.c      the node: dials out, hands sessions to dropbear -i
                connect.c    the operator side: an ssh ProxyCommand
                relay.c      a rendezvous relay, one session per socket
                util.c       randomness, base64, sha1 for the ws accept
                buffer.c     the one growable buffer every layer moves bytes through
scripts/        build.sh, build-dropbear.sh, build-mbedtls.sh
patches/        three diffs against dropbear; no dropbear code is copied
tests/e2e.sh    the gate
tests/mux-probe.py
                the relay's framing rules as a gate: the prepend/strip
                asymmetry, the 1009 close for a bare node frame, the 1003
                close for a text frame on a data leg. No network, no token.
docs/           the measurements, which are the real documentation
vendor/         does not exist, on purpose: inputs are fetched and pinned
```

## Conventions

* `sh` for scripts. `bash` only where a job needs it. `zig cc` for all C.
* Comments explain **why**, and carry the measurement. A comment restating the
  line is noise; a comment saying why the obvious thing is wrong is the only
  documentation that survives the next edit.
* `⛔` marks a trap, a measured failure, or a silent-failure guard. It is used
  consistently so a reader can scan for them.
* Assert on the **artefact**, never on the source and never on a build's exit
  status.
* Read exit codes from the process that produced them, never through a pipe. A
  pipe reports the last command's status, so `test | tee log` reports `tee`'s.
* Never commit a credential. Relay tokens, host keys, private keys, `passwd`
  files and built artefacts are all ignored, with a note saying why.

## Traps, so you do not rediscover them

* `--disable-static-programs` **does not exist** in dropbear's configure. It
  warns and continues. The lever is the `STATIC=` value.
* The passwd shim is **glibc-only**: musl's `RTLD_NEXT` is `NULL` for a libc
  symbol.
* A **musl dropbear cannot be built** with zig cc: `-rdynamic` fails autoconf's
  `-c` probe, `-pie` gives static-pie. The builder refuses it by name.
* zig 0.13 **cannot build glibc riscv64** (`.cfi_label`).
* **cmake writes into the mbedTLS source tree**, so one tree per target, or
  parallel builds overwrite each other.
* `dropbear -i` **exits on a character-device stdin**; probe it on a socketpair.
* `/etc/shells` decides whether a login works; the shell patch handles it.
* The shim **replaces** the passwd database rather than adding to it.

Each of these is measured in `docs/decisions-tls.md` with the command that
produced the number.

## The multiplexed reverse path, and what is still not implemented

**The multiplexed reverse path is implemented and measured live.** One
long-lived node socket carries many sessions, told apart by a 32-hex id on
every frame. Measured 2026-09-28 against `tcp.ssh.relay.ajam.dev` through a
443-only CONNECT proxy: two concurrent pubkey sessions on **one** node socket,
one sleeping while the other transferred 270177 bytes back byte for byte.

The **forward** path and the **rendezvous** path are both implemented and both
are proven with real sessions. The forward path is proven by hand, not by the
gate: see **B10**.

Still open, and named in `docs/relay-issues.md`:

* **R2** — a scheduled CI job that drives a real relay. It needs a network and
  a credential, so it cannot run on every commit. The framing rules it would
  have guarded are asserted locally by `tests/mux-probe.py` instead.
* **R8** — fetch the relay's own reference operator, pinned, so protocol drift
  is visible rather than discovered.
* **B12**–**B14** — defects in the relay and in its reference operator. Reported,
  not fixed here; B12's consequence is documented because a client must not
  treat the id in an operator frame as addressing.

## Traps added since the multiplexer shipped

* ⛔ **A TEXT FRAME ON A DATA LEG IS CLOSE 1003, A BARE NODE FRAME IS CLOSE
  1009, AND DATA SENT BEFORE `ready` IS CLOSE 1008.** Three different bugs,
  three different closes, and in C the opcode is chosen by the frame writer. A
  client that logs all three as "framing error" cannot tell which it has.
* ⛔ **THE OPERATOR SENDS NOTHING UNTIL IT SEES `ready`.** Writing the ssh
  banner first is torn down (operator 1008 `wait for ready`, node 1003
  `unknown session id`). `connect` holds stdin.
* ⛔ **STDIN EOF IS NOT "SESSION OVER".** ssh writes its whole conversation and
  then closes stdin, but the reply is still coming. A websocket Close there
  tells the relay to tear the session down, and the operator exits having read
  nothing.
* ⛔ **EVERY SOCKET IS NON-BLOCKING, AND `wrap_fd` IS WHERE THAT IS SET.** Three
  of the four constructors bypassed it, so the local relay and every socket the
  relay accepted were blocking. The old blocking `ws_read` hid it; a loop that
  must also service another leg cannot.
* ⛔ **THE TLS BIO IS NON-BLOCKING.** `mbed_recv` returns
  `MBEDTLS_ERR_SSL_WANT_READ` rather than sleeping and retrying. A blocking BIO
  is correct for a blocking caller and a hang for a multiplexed one.

## Related work

* The Rust original this reimplements in C:
  <https://github.com/Azathothas/podbox/pull/67>
* The shims, `errandsh` and the sandbox bootstrap, which this repository
  fetches rather than carries: <https://github.com/talaria0101/sandhome>
