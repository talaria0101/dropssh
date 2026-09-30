# HANDOFF

Where this repository is, what is proven, and what is not. Written 2026-09-28.
Every claim here has a command or a log line behind it, and the ones that do
not are marked as such.

**Read `AGENTS.md` first.** It is self-contained and it routes to everything
else. This document is for whoever picks the work up, not for the code.

---

## The gate, and what it is

| gate | what it proves | last run |
| --- | --- | --- |
| `tests/e2e.sh` | a release artefact carries a **real session** | **36/36, exit 0** (2026-09-30; case 36 is the SOCKS byte path) |
| `tests/mux-probe.py` | the relay's framing rules, locally, 14 cases | green |
| `tests/wsmove-test.c` | one owner per websocket session (U2) | 7/7 |
| `tests/token-test.c` | the bearer-token contract (issue #13) | 14/14 |
| `tests/socks-policy-test.sh` | the SOCKS destination decision | 10/10 |
| `tests/socks-forward-test.sh` | a SOCKS forward carries bytes, gated via e2e | 3/3, then 36/36 in the gate |
| `tests/plant-matrix.sh` | every guard fails when its defect returns | 14 of 16 rows red (SOCKS publish row added) |
| `tests/relay-session.sh` | a **real session against the real relay** | green against r12 |

```sh
./scripts/build.sh --target x86_64-linux-musl --full --out dist/x86_64-linux-musl
./tests/e2e.sh dist/x86_64-linux-musl
sh tests/relay-session.sh dist/x86_64-linux-musl
```

⛔ **The last one needs a network and reaches a third party's deployment.** It
mints its own pair, so it needs no credential, but it is not part of the e2e and
must not be put in one.

---

## What is DONE and proven

**U1, U2, U3 — the three known-unguarded items.** All closed, all with the
plant run and counted. U2 went 0/6 → 4/4 named failures. U3 went 0/6 → 25/25.

⛔ **U3's closure corrected the project's own record.** The claim "the window is
narrower than a run" was true of the scenario it was measured on — a node
disconnects while the operator stays attached and *idle*. Closing **both**
sockets at once, which is what a real teardown looks like, makes the window
wide. U3 needed a different **scenario**, not a fault-injection hook. The hook
is kept, validated, and documented as not having closed U3.

**#13 step 1 — token issuance and verification.** A relay issues pairs and
verifies them. A token is a bearer credential, not a handle, which is what makes
migration between relays possible. Role separation, the wrong-key case, expiry,
and the compatibility rule (a relay with **no** key accepts every token) are all
in the gate, and three plants are caught by the assertion written for each.

**#13 step 2 — a real session against the real relay, with no credential.**
See below; this is the newest and the one I got wrong about twice.

**R2 — done.** ⛔ I had written that it needed three repository secrets and that
a pair "cannot be obtained from the outside". **That was wrong.** The relay's own
`llms.txt` at r12 says `POST /v1/pair` with an empty body is **self-service**
and that the agent mints it itself. R2 never needed a secret. The lesson is
recorded in the issue and in the code: ⛔ a claim about someone else's service,
made from memory and carried into prose, drifts from the service. Fetch it.

**#10, #11, #4/#8, R7, R8, R9.** The three wstunnel adopts, the two websocat
cases, the operator-side SOCKS5 and the reconnection budget, the CA bundle in the
release, the relay's own document fetched with its version, and `dropbear -Y`.

**Defects found by writing the tests, not by reading the code** — eight of them,
including a **silent data loss** (`relay.c` clamped an operator's frame to the
node's `maxFrameBytes`, so 300000 bytes arrived as 65536 with no close and no
log) and a **NULL dereference** on any write to a closed or moved-from session.

---

## What is NOT done, precisely

**1. The SOCKS5 forward carries no bytes.** ⛔ This is the one piece of shipped
work that does not do what it says. The listener, the policy, the destination
validation and the node's dial are all measured; the last mile is not.

*Measured:* the node opens the forward and then blocks on a mutex before
publishing the session. Every run, same line, `futex_do_wait`.

*Three designs were tried and none was the cause* (all in
`tests/socks-forward-test.sh`):

1. destination in the `open` once, session id still prefixed per frame. ⛔ The id
   is *addressing*, not a destination encoding — a frame on a multiplexed socket
   with no id belongs to no session.
2. the forward as an ordinary `Client` over a socketpair. ⛔ My second version
   read the node's websocket to wait for `ready` — a **second reader on a shared
   socket**, the rule at the top of `relay.c` — and deadlocked, failing as
   somebody else's silence.
3. the SOCKS `CONNECT` reply after the node's `ready`.

*Where to look:* the node blocks between `s->is_socks = 1` and
`pthread_mutex_lock(&m->list_lock)` in `on_control` (`src/serve.c`). Every
`list_lock` acquisition was read; none obviously holds it across that point.
⛔ **The next thing to do is find the lock, not to redesign the forward.**

⛔ **The case is deliberately NOT in the gate.** A gate entry that is always red
is a gate nobody reads.

**2. The ladder's third line.** A session migrating between two *different*
relays without being re-created, with the log saying which relay carried it.
Unbuilt. Migration between two of ours sharing a key is proven.

**3. No sanitizer has ever been run on any of this.** There is none on this
machine. Reviews 1 and 2 are **traces, not instruments**, and the two
plant-matrix rows that cannot go red are exactly what one would answer.

⛔ The two rows, and why:

* **`ws_close` not setting `closed`** — undetectable, because a `WsSession` is
  never re-armed after `ws_close`, so "closed with a live transport" cannot be
  constructed. The flag is still load bearing (a framing error sets it and
  leaves `t` alone); proving that needs a decoder stub this repository lacks.
* **the node refcount** — a relay with it removed still served 379 writes
  across a disconnect. ⛔ `node_done` ends with `ws_close(ws)`, so the session is
  freed *before* the context, and `ws_write` on a closed session returns -1.
  ⛔ **The refcount is defence in depth and the ORDERING is what holds**, which
  is the opposite of what the B-list says.

**4. A static dropbear.** R9 removed the *requirement* for the shim.
DONE 2026-09-30 as the default: `build.sh` builds a static musl server
unless `--dropbear-target` names gnu; all six arch servers build; the e2e
gate proves logins on the default path. Dynamic glibc is the opt-out.

**5. The case-3 close-code flake is unrooted.** 1/100 pre-change, 3/100 after.
Pre-existing. Never investigated.

**6. `--retry-budget` measured only against an absent relay.** UPDATE
2026-09-30: measured against a present-but-stalling relay with
`tests/slow-relay-probe.py`. The node pings unanswered x3, declares the relay
dead at ~60 s, tears down, retries, exits 4 with the give-up line. Doing that
measurement found and fixed a teardown double-close in `serve.c` (`ws_close`
frees the transport; `t->close(t)` after it is use-after-free).**

---

## Things a next session will trip over, in the order they will

* ⛔ **Test work dirs must live where dropbear's permission walk passes.**
  `checkpubkeyperms` walks EVERY component of the authorized_keys path up to
  the home dir or `/`, refusing group/other-writable ones. A work dir under a
  loose `/tmp` (mode 1777) fails every non-root login with `Permission denied
  (publickey)` and a server line naming `/tmp` -- while e2e session1 passes
  on the same runner, because e2e works under `$HOME`. Measured on CI
  2026-09-30 across three red cycles that blamed the shim, the file content,
  and the home entry in turn. All login tests base their work dir at `$HOME`
  when writable, else the checkout. A root-only failure that passes as root
  is this until proven otherwise.

* ⛔ **`/tmp` is cleared between turns.** Every build artefact and every
  `mktemp` work dir disappears. Rebuild before concluding anything from a
  previous turn's `/tmp`.
* ⛔ **`$HOME` is a zfs mount that will not execute a new file.** A mode-0755
  binary there answers "Permission denied". Compiled tests must be copied to
  `$TMPDIR`. `wsmove-test` and `passwd-file-test` both handle this; anything
  new must too.
* ⛔ **`bind(2)` INET is refused at uid 0.** AF_UNIX is fine. Anything that
  listens on TCP cannot be tested here, which is why `--socks unix://` exists.
* ⛔ **The egress CONNECT proxy is also the only resolver.** Clearing it makes
  DNS fail, so "clear the proxy" is not a way to reach something directly.
* ⛔ **`/etc/passwd` does not exist**, so `ssh(1)` needs the shim to start at
  all. The **client** gets the shim; the **server** under test does not, and
  conflating them produces `No user exists for uid 0`, which is OpenSSH
  complaining about the wrong process.
* ⛔ **A log line is an interface.** The e2e greps for
  `operator opened session`. Rewording it to report a session's mode broke the
  two-concurrent-sessions check with `the node re-registered 1 times for 0
  sessions`, which names nothing.
* ⛔ **`relay_parse_uint` needs its key quoted, with the quotes.** Given a bare
  key it finds the opening quote of the value and lands on the closing quote.
  `relay_parse_string` builds the quoted key itself, so the two disagree and
  neither says so.
* ⛔ **Bare `wait` in `sh` returns when the LAST job finishes**, so one early
  finisher makes the other look hung.
* ⛔ **A `sched_yield()` loop takes microseconds; a thread reaching a close and
  a free takes milliseconds.** The 2000-yield park in `relay_fault` was why
  `write-in-flight` needed to become a condition wait.
* ⛔ **`.deps/dropbear/x86_64-linux-gnu` keeps applied patches between runs.**
  `git checkout -- src/` there before a build, or a patch's idempotency marker
  says "already present" and it never applies.

---

## The standing rule, and the evidence for it

This repository has shipped the claim "every guard was proven to fire" **four
times**, and it was false four times. The plant matrix exists because of that.

⛔ **A claim that a guard fires is a claim about a counterfactual.** Reading a
test shows what it *would* check; only running the plant shows what it *does*.

```sh
./tests/plant-matrix.sh          # ~25 min, network-free except two rows
```

⛔ And the matrix's own faults, which cost more time than any product defect
here: a plant that removes the **instrument** as well as the defect (and prints
NOT CAUGHT on a broken build); a row that **hangs**, which is a row that never
reports; a matrix that prints nothing for nine minutes because output through
`setsid` to a file is block-buffered (use `stdbuf -o0`); and a case that reports
a **crash as its own setup failure**, three runs in a row with a perfect 3/3.

---

## If you pick up the SOCKS forward

Done 2026-09-30; see the entry above. The lock described below never
existed: the publish path sat inside the ssh-spawn branch, so a SOCKS
session never reached any mutex. Reproduce (now green) with:

```sh
sh tests/socks-forward-test.sh dist/x86_64-linux-musl
```

The section below is kept so the wrong diagnosis stays visible next to
the correction.

⛔ Read the node's own log, not the client. A connected SOCKS forward is not a
working one, and the client's silence cannot tell you which end failed — that
distinction cost most of the debugging.

---

## 2026-09-30: the SOCKS forward carries bytes

Item 1 of "what is NOT done" is done. The `futex_do_wait` diagnosis in the
section above was wrong: the node never reached a mutex at all. The publish
path in `src/serve.c`'s `on_control` sat inside the ssh-spawn `else` branch,
so a SOCKS session was dialled, logged, leaked, and never published, never
sent `ready`, never pumped. The relay half had a second defect of its own: a
raw byte pump wrote into a socketpair where `client_thread` reads websocket
frames. Both fixed, both proven:

* `sh tests/socks-forward-test.sh dist/x86_64-linux-musl` — 225 bytes each
  way through a live destination, 3/3 runs, then gated as e2e case 36
  (**36/36, exit 0**).
* Plant P1 (the session dropped before publish) fails the forward test,
  exit 1; the fix passes. Row added to `tests/plant-matrix.sh`.
* A node that never answers `ready` gets a bounded SOCKS refusal (20 s),
  not a hang (`tests/socks-wait-probe.py`, manual check).
* Case-3 flake sampled 0/100 on this build (`tests/case3-loop.py`).

What is still not done, unchanged: the ladder's third line (cross-relay
session migration), a sanitizer run (no libasan/libtsan on this machine
either, re-confirmed), a static dropbear, and `--retry-budget` against a
present-but-slow relay. The case-3 flake is sampled, not rooted.

---

## Next session: publish test static binaries -- DONE 2026-09-30 except the tag

1. Builder support: DONE. `build-dropbear.sh` builds static musl by default
   (`STATIC=1`, linkage asserted), dynamic glibc on explicit request; shim
   built for the GNU sibling when it compiles, skipped with a note otherwise.
2. Scale proof: DONE for x86_64 (full e2e 36/36 on the default dist); all six
   arch servers compile. Live-relay session against the static server: 2/3
   green 2026-09-30. The first run failed (1003 unknown session id, ssh 255)
   inside the relay's own redeploy window (r12 to 2026-09-30-r1, same hour);
   two reruns with identical artefacts passed, and the re-fetched spec holds
   5/5 with additive-only changes (capacity accounting, reason truncation
   refined). No client change indicated; treat run 1 as deploy churn unless
   it recurs.
3. CI: DONE in-tree (matrix builds six static servers, glibc-optout job,
   flipped linkage asserts, updated release notes). Runs on push.
4. Docs: DONE (this file, decisions-tls, AGENTS, README, open-issues, CI text).
5. Publish: tag v0.2.0 and push the tag. The release job publishes from it.

## Session after next: the remainder

* Case-3 flake root cause: sampled 0/100 twice, then a 500-run died around
  iter 293 with refused connections. Prime suspect is relay thread
  accumulation under churn; rerun with thread sampling to confirm, then fix.
  (`tests/case3-loop.py`.)
* Ladder's third line: cross-relay session migration. Blocked on a mechanism
  decision first (tokens are key-bound by design, so migration means re-pair
  plus id remap, not token sharing). No third party needed: two local relays
  with different keys are the fixture.
* Static as the default: release decision, operator's call. Proof exists;
  packaging, CI and docs changes do not.
* Release tag for the SOCKS work and the static test binaries: operator's
  version string, then push and publish.
* Issue closes with proof: #4 (SOCKS capability fully delivered) is ready to
  close with the gate log; the rest need maintainer verdict calls.
