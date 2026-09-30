#!/usr/bin/env python3
"""slow-relay-probe: --retry-budget against a PRESENT but stalling relay.

The gate measures the budget against an ABSENT relay (connect fails fast).
This fixture is the other half: a relay that completes the node's upgrade,
sends hello, then stalls forever. The question is what the node does: exit 4
on the budget, or wait past it.

Modes (--mode):
  upgrade-stall  accept the connection, never answer the upgrade. The node
                 times the upgrade out after 20 s and the wait consumes the
                 attempt budget like any other refusal.
  hello-stall    complete the upgrade, send hello, then silence. MEASURED
                 2026-09-30: the node pings unanswered x3, declares the relay
                 dead at ~60 s, tears down, retries, exits 4 on the budget.
  open-stall     hello, then an open for a session nobody operates, then
                 silence. Present but UNRUN.

Only the first connection is served; redials queue in the listen backlog
and hit the same 20 s upgrade timeout, which is itself a budget consumer.

Usage: slow-relay-probe.py DROPSHH_BIN WORKDIR MODE BUDGET
Prints the node's exit code, wall time, and the give-up line if any.

Note the budget counts retries after the first dial: budget 1 dials twice
(measured: two 20 s upgrade timeouts, then "giving up after 1 attempts",
exit 4). That is the existing semantic, recorded here rather than judged.
"""
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import time

DROPSHH, WORK, MODE, BUDGET = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
os.makedirs(WORK, exist_ok=True)
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SOCK = os.path.join(WORK, "slow.sock")
try:
    os.unlink(SOCK)
except OSError:
    pass


def send_frame(c, opcode, payload):
    h = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        h += bytes([n])
    elif n < 65536:
        h += bytes([126]) + struct.pack(">H", n)
    else:
        h += bytes([127]) + struct.pack(">Q", n)
    c.sendall(h + payload)


def handle(c):
    if MODE == "upgrade-stall":
        # Answer nothing at all: hold the accepted socket open until the
        # node goes away. The node's 20 s upgrade wait is what times out.
        c.settimeout(5.0)
        while True:
            try:
                if not c.recv(65536):
                    return
            except socket.timeout:
                continue
            except OSError:
                return
    c.settimeout(15)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = c.recv(4096)
        if not chunk:
            return
        buf += chunk
    head = buf.split(b"\r\n\r\n")[0].decode("latin1")
    if MODE == "upgrade-stall":
        pass  # already stalling above; this line is never reached
    key = [l[19:] for l in head.split("\r\n")
           if l.lower().startswith("sec-websocket-key:")][0]
    accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest())
    c.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
              b"Upgrade: websocket\r\n"
              b"Connection: Upgrade\r\n"
              b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
    if MODE == "upgrade-stall":
        return  # unreachable: upgrade is never answered in this mode
    hello = json.dumps({"type": "hello", "version": 1,
                        "maxFrameBytes": 65536,
                        "maxSessions": 64}).encode()
    send_frame(c, 0x1, hello)
    if MODE == "open-stall":
        send_frame(c, 0x1, json.dumps(
            {"type": "open", "id": "a" * 32}).encode())
    # stall: hold the socket open, answer nothing, until the node goes away
    c.settimeout(1.0)
    try:
        while True:
            d = c.recv(65536)
            if not d:
                return
    except socket.timeout:
        pass
    except OSError:
        pass


srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(SOCK)
srv.listen(8)
srv.settimeout(30)
print("slow-relay: mode=%s budget=%s" % (MODE, BUDGET), flush=True)
node = subprocess.Popen(
    [DROPSHH, "serve", "--relay", "unix://" + SOCK, "--name", "slow1",
     "--retry-budget", BUDGET, "--server", "sleep 60"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    c, _ = srv.accept()
except socket.timeout:
    print("slow-relay: node never dialled")
    node.terminate()
    sys.exit(2)
handle(c)
t0 = time.time()
try:
    out, _ = node.communicate(timeout=120)
except subprocess.TimeoutExpired:
    node.kill()
    out, _ = node.communicate()
    print("slow-relay: node still alive after 120s (budget=%s)" % BUDGET)
    print(out.decode(errors="replace")[-1500:])
    sys.exit(3)
dt = time.time() - t0
print("slow-relay: node exited %d after %.1fs" % (node.returncode, dt))
full = out.decode(errors="replace")
open(os.path.join(WORK, "node-full.log"), "w").write(full)
print(full[-1500:])
