# Why dropssh links a TLS stack instead of writing one

Date: 2026-09-27. Measured in the reference cage, not assumed.

## The measurements

| what | how it was measured | result |
| --- | --- | --- |
| relay TLS version | `curl -v` through the cage proxy | TLS 1.3, `TLS_AES_256_GCM_SHA384`, key exchange **X25519MLKEM768** (post-quantum hybrid) |
| TLS 1.2 to the same relay | `curl --tlsv1.2` | 200, so TLS 1.2 is offered and accepted |
| X25519 only | `curl --ciphers X25519 --tlsv1.3` | 200 |
| system TLS libraries | `ls /usr/lib/x86_64-linux-gnu/lib{curl,mbedtls,openssl,wolfssl,gnutls}.so*` | none present |
| system TLS headers | `ls /usr/include/{curl/curl.h,mbedtls/ssl.h,openssl/ssl.h}` | none present |
| static archives | `ls /usr/lib/x86_64-linux-gnu/*.a` | none present |
| `SOCK_RAW` | a C program, `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` | `EPERM` |
| ping sockets | `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` | `EACCES` |
| `bind()` on 127.0.0.1:443 | `bind()` | `EACCES` |
| `/dev/ptmx` | `open()` | `ENOENT` |
| name resolution | `getaddrinfo("tcp.ssh.relay.ajam.dev")` | `EAI_AGAIN` |
| proxy CONNECT, one name | `CONNECT tcp.ssh.relay.ajam.dev:443` | `200` |
| proxy CONNECT, another name | `CONNECT tcp-1.ssh.relay.ajam.dev:443` | `504 the name did not resolve in time` |

## What follows from it

**1. A statically linked dropssh cannot run in a cage, and the reason is the
shim, not the size.** Measured in this cage, with the same patched binary
built both ways:

- dynamic, no shim: `Login attempt for nonexistent user from localhost:...`
- dynamic, `LD_PRELOAD=fakepwd.so`: `User 'root' has invalid shell, rejected`
- dynamic, shim plus a passwd file naming `/bin/sh`: `Pubkey auth succeeded`,
  the command ran, exit 0

A static binary carries its own libc, so `LD_PRELOAD` cannot reach it and the
first line above is what it always says. `--disable-static-programs` is
therefore load-bearing and is asserted in the builder, not passed and hoped
for. The "single static binary" goal is met by the **other** half: the dropssh
side (`serve`, `relay`, `hostkey`) is static, and the dropbear side is
dynamic. They are separate artefacts with separate jobs, and conflating them
is what produces a binary that compiles and cannot log anyone in.

**2. The TLS stack is a build input, not a header dropssh writes.**
`transport_tls` needs a context, not a socket. Writing a TLS 1.3 client means
X25519, AES-GCM, SHA-384, HKDF, transcript hashing, a certificate parser and a
trust store, and the relay's own negotiated group is the post-quantum hybrid
X25519MLKEM768, so a client that only offers plain X25519 is choosing to be the
one conversation that fails. That is a large, security-critical surface to add
to a program whose purpose is to be an ssh server. The two options that do not
involve writing it are libcurl (what the reference client uses, and the reason
the reference path is proven) and mbedtls (smaller, no external process).
Both are vendored by the builder and recorded in `BUILDINFO`, so a binary that
was built here says which TLS implementation it carries.

**3. pwnat's mechanism cannot work here, and the relay does not need it.**
pwnat is ICMP TTL-manipulation between two peers: `src/packet.c` opens
`SOCK_RAW`/`IPPROTO_ICMP` and sets `IP_HDRINCL` to forge the TTL on an echo
request so the far end learns the NAT mapping. Measured here: `SOCK_RAW` is
`EPERM` and ping sockets are `EACCES`, so the mechanism has no way in. It is
also unnecessary: the relay is ordinary HTTPS on 443, which traverses NAT in
both directions without a raw socket, a bind, a third party or an inbound
hole, and the ssh stream stays end-to-end encrypted through it. pwnat's trick
buys a direct path; the relay buys a path that works with no privileges at
all, and pays for it with one hop that sees ciphertext.

**4. The proxy resolves, and whether it resolves is a property of the path.**
The same proxy answered `200` for one relay host and `504` for another in the
same second. So the client must hand the name over unresolved, and must not
assume a name it cannot resolve is a relay that is down. This is why
`transport_tcp` sends the name in CONNECT and why `dropssh_resolve` exists
separately for the direct route.

## What is not settled

- Whether the default should be `libcurl` or `mbedtls`. Both work; the choice is
  made at build time and recorded. `libcurl` is what the e2e proves today.
- Certificate verification is on by default and `--insecure` exists, but the
  e2e runs with a real public certificate, so the insecure path is exercised
  only by its own negative test.

## Two defects found by running it, both silent

**`parse_path` on a file.** mbedTLS has two loaders: `parse_file` and
`parse_path`, and `parse_path` walks a *directory* with `readdir`. Calling it
on a regular file returns `MBEDTLS_ERR_X509_FILE_IO_ERROR`, which reads as
"the file could not be opened" on a file that opens fine and yields 170
certificates through `parse_file`. Measured, same static binary, same file:

```
parse_path("/tmp/ca.crt")   rc=-10496  certs=1
parse_file("/tmp/ca.crt")   rc=0       certs=170
parse_path("/etc/ssl/certs") rc=0      certs=510
```

**A NULL that terminated the search.** The candidate list was
`{getenv(...), <three paths>, NULL}` and `getenv` returns NULL when the
variable is unset. So on any machine without `DROPSSH_CA_BUNDLE`,
`SSL_CERT_FILE` or `CURL_CA_BUNDLE`, the loop stopped at index 0 and never
looked at the well-known paths, and dropssh said "no CA bundle found" with
`/etc/ssl/certs/ca-certificates.crt` sitting right there. The slot is now `""`,
which the loop skips, and the terminator is only the final NULL.

The second one is the more interesting shape: the fix for the first defect is
what exposed the second, because the working invocation had the environment
variable set and the failing one did not. A defect that only appears when an
optional thing is absent is invisible to any test that supplies it.

## Three defects in the pump, and the isolation that found each

**A dropped first read.** The node's read loop has to read far enough to see
that a session has started, and that read consumed the beginning of the ssh
version string. It was not forwarded, so dropbear saw an empty stream and
logged `Exit before auth`, which names authentication and is a framing
problem. The bytes are now the server's first input, written before the pump
starts.

**A deadlock in the byte pump.** This one cost the most and is the reason the
other two are worth writing down. The pump was one loop: poll the server
socket, then call `ws_read` on the relay. `ws_read` does not return until it
has payload, because an idle ssh session must not look like a closed one. So
the moment the client stopped sending, the call blocked inside `ws_read` and
the server-to-relay direction was never serviced again.

The symptom read exactly like a broken transport: the client sent `exec`, the
server authenticated it, ran it, and wrote its output, and none of it moved.

What found it was isolating both legs before suspecting either:

| leg | how it was tested alone | result |
| --- | --- | --- |
| relay splice | two raw websocket clients, one `/v1/node/t1` and one `/v1/connect/t1`, bytes sent each way | `client->node: b'HELLO-FROM-CLIENT'`, `node->client: b'HELLO-FROM-NODE'` |
| `dropbear -i` on a socketpair | a real `ssh` client against a `dropbear -i` on a socketpair, no dropssh in the path | `OUT`, uid 0, exit 0 |

Both good, so the fault had to be in the code that joined them, and it was.
A poll loop cannot fix this, because one of the two sources has no pollable
descriptor: the relay's readiness is decided inside the TLS and framing
layers, not by a file descriptor. Two threads is the shape that matches two
independent byte streams.

**A close that raced the output.** When the server's socket reaches EOF the
command has already written its output and the exit status is on its way.
Calling `ws_close` there closes the websocket and can lose both, which is how
a command that ran to completion reported nothing. It is now a half-close
(`ws_shutdown_tx`): a Close frame, and the session stays readable.

## The passwd shim is glibc-only, and that decides the dropbear target

Measured 2026-09-27, same `fakepwd.c`, same `LD_PRELOAD`, same test program
that calls `getpwnam("root")` in a cage with no `/etc/passwd`:

| dropbear linkage | `getpwnam("root")` with the shim |
| --- | --- |
| glibc, dynamically linked | `FOUND` |
| musl, `-rdynamic` (reports "dynamically linked") | `not found` |
| musl, static-pie | `not found` |

The cause, from a program that asks the dynamic linker directly:

```
gnu :  getpwnam in main program: yes    RTLD_NEXT getpwnam: resolves
musl:  getpwnam in main program: no     RTLD_NEXT getpwnam: NULL
```

`RTLD_NEXT` is how an `LD_PRELOAD` shim finds the real function to chain to.
On musl it resolves to NULL for a libc symbol, so the interposition never
takes effect no matter how the binary is linked. **musl + LD_PRELOAD cannot
substitute for a passwd database**, and no linker flag changes that.

Two consequences, both of which are the opposite of the obvious guess:

1. **The dropbear server is built for a glibc target.** Not musl, and not
   static-pie. `scripts/build-dropbear.sh` names the dynamic loader per target
   and the linkage check refuses both `statically linked` and
   `static-pie linked`, because static-pie is the case that looks fine and
   fails every login.
2. **The "single static binary" goal is met by the dropssh side, and the
   dropbear side is dynamic.** These are two artefacts with two jobs. The
   binary a user downloads and runs, the one that has to work in a cage with
   no libc, is `dropssh`, and it is static. The ssh server is a separate file
   that must be dynamically linked to be useful at all.

The alternative, which was considered and measured against: make dropbear not
need the shim, by giving it a passwd database through the filesystem. That is
`dropbear -Y FILE`, shipped as R9: a server with no `LD_PRELOAD` in its
environment authenticates, measured in the gate. The release still ships the
shim and still builds the server dynamic glibc by default; what changed is
that the split is now a build choice rather than a constraint. (This paragraph
once said the patch was not written yet. It is written, shipped, and gated.)

## A dynamic musl dropbear is not buildable; a static one serves (2026-09-30)

Both measured 2026-09-27 in CI, and both are why the release matrix is split.
The heading above once said a musl dropbear is not buildable at all. That was
true while the server needed the shim, and it is still true of a DYNAMIC musl
server. It is no longer true of a STATIC one, measured 2026-09-30:

**musl dropbear.** The shim needs a dynamically linked server, and under
`zig cc` a musl binary is dynamic only with `-rdynamic`:

```
zig cc -target riscv64-linux-musl -pie      t.c  ->  "pie executable ... static-pie"
zig cc -target riscv64-linux-musl -rdynamic t.c  ->  "LSB executable"        (dynamic)
```

`-rdynamic` then fails autoconf's first probe, which compiles with `-c`:

```
ld.lld: error: -r and --export-dynamic may not be used together
```

and autoconf reports `cannot compute suffix of object files: cannot compile`,
which names the compiler and not the flag. So there is no flag that both yields
a dynamic musl binary and survives a `-c` probe: `-pie` compiles and produces
exactly the artefact this build exists to refuse, and `-rdynamic` is rejected at
the first step. `build-dropbear.sh` refuses a musl target and says so, and the
CI has a job that exercises that refusal on every run, because a guard nobody
can see is not a guard.

**glibc riscv64.** zig 0.13 ships a glibc whose riscv64 startup uses an
assembler directive its own linker rejects:

```
/usr/lib/zig/libc/glibc/sysdeps/riscv/start-2.33.S:48:2: error: unknown directive
  .cfi_label .Ldummy
```

So riscv64 is a dropssh target and not a dropbear one. The split is the same on
both sides of the project for the same reason: **dropssh must be musl to run in
a cage, and dropbear must be glibc to be preloaded.**

**The dropbear target is therefore named, not derived.** `--target` is the
dropssh target; `--dropbear-target` is the server's, defaulting to
`x86_64-linux-gnu`, the one target known to work. Deriving the glibc sibling of
a musl target looks right and produces a musl server, which cannot be built.

## A login shell that exists is a login shell

Measured on a GitHub Actions runner, 2026-09-27, with a passwd entry naming
`/bin/sh`, that shell present and executable, and `/etc/shells` present:

```
Login attempt with wrong user root from localhost:...
Exit before auth from <localhost:...>: (user 'root', 0 fails)
```

The same binary on a host with **no** `/etc/shells` works, because dropbear's
`getusershell()` then returns a compiled-in fallback list. So whether a login
succeeded depended on whether a *policy file* existed, which is exactly backwards
for a cage: `/etc/shells` is an administrator's list of shells users may log in
with, and a cage has one user, no administrator and no policy. There the check's
only effect is to refuse a shell that is present.

`patches/dropbear-login-shell-tolerance.patch` consults the list first, so a
host that does have a policy keeps it, and accepts a shell that exists and is
executable when the list does not name one. It is not a way around a policy:
anyone who can write `/etc/passwd` can already name any shell, and where a
policy exists it still wins.

The e2e asserts both halves, because a tolerance with only one half is a bug:

* a login whose shell exists is **accepted**
* a login whose shell does not exist is **refused, and says which shell**

The second case earned its place immediately. Its first version read `ssh`'s exit
status, and a refused login exits non-zero exactly like a broken one, so the
branch was backwards and the suite reported a nonexistent shell as reached,
against a server log saying `User 'ghost' has an invalid shell ... rejected`.
The assertion is on the server's words, because they are the only thing that
distinguishes refused from broken. Two more defects were in the same case: a
`grep -q` over a log that carries dropbear's peer address in non-text bytes,
which reports "Binary file matches" and exits 0; and an ssh user that the test
harness computed and then never passed to `ssh`, so every login was attempted as
root.

---

## 2026-09-30: a static-pie musl server serves a real login

Built with `zig cc -target x86_64-linux-musl`, `STATIC=1`, the setgroups and
passwd-file patches, and one new patch, `patches/dropbear-unix-peer-tolerance.patch`:

* musl `getnameinfo` refuses AF_UNIX outright while glibc prints the path.
  `serve` always runs the server on a socketpair, so a static server exited
  in `getaddrstring` before any session, with `Failed lookup: Unrecognized
  address family`. The patch names a unix peer plainly (`unix:0`); it is wired
  into `build-dropbear.sh` for all targets and is inert where glibc already
  formats the peer.
* Measured with `tests/static-server-test.sh`: a real pubkey login through a
  local relay as the running uid, server environment with no shim, exit 0.

What this does not change: the default build stays dynamic glibc, the builder
still refuses a musl target (a static server is a flag that does not exist
yet, not a target the matrix builds), and static-pie is still refused as a
*silent* artefact — the difference is that with `-Y` and the peer patch it is
no longer silent about the wrong thing. Switching the default is a release
decision recorded in HANDOFF, not a follow-up measurement.
