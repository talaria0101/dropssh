#!/usr/bin/env python3
"""socks-wait-probe: a node that never answers ready must get a bounded
SOCKS refusal, not a hang. Manual check for the relay's ready wait.
Usage: socks-wait-probe.py DROPSHH_BIN WORKDIR
"""
import importlib.util
import os
import socket
import struct
import subprocess
import sys
import time

DROPSHH = sys.argv[1]
WORK = sys.argv[2]
os.makedirs(WORK, exist_ok=True)

spec = importlib.util.spec_from_file_location(
    "muxprobe", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "mux-probe.py"))
mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mux)

sock_path = os.path.join(WORK, "waitsocks.sock")
relay = subprocess.Popen(
    [DROPSHH, "relay", "--listen", "unix://" + sock_path,
     "--socks", "unix://" + os.path.join(WORK, "s.sock"),
     "--socks-node", "n1",
     "--socks-dest", "unix://" + os.path.join(WORK, "d.sock")],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(200):
        if os.path.exists(os.path.join(WORK, "s.sock")):
            break
        time.sleep(0.05)
    assert os.path.exists(os.path.join(WORK, "s.sock")), "socks never bound"

    # fake node: upgrade, read hello/open, never answer ready
    node = mux.connect_relay(sock_path)
    node.settimeout(15)
    buf = mux.handshake(node, "/v1/node/n1")
    rn = mux.Reader(node)
    rn.buf = buf
    deadline = time.time() + 8
    saw_open = False
    while time.time() < deadline and not saw_open:
        if not rn.feed(0.3):
            break
        while True:
            f = rn.take()
            if f is None:
                break
            if f[0] == 0x1 and mux.parse_json(f[1]).get("type") == "open":
                saw_open = True
    # do not answer; keep the socket open so the relay keeps waiting
    t0 = time.time()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(os.path.join(WORK, "s.sock"))
    s.sendall(bytes([0x05, 0x01, 0x00]))
    assert s.recv(2) == bytes([0x05, 0x00])
    host = ("unix://" + os.path.join(WORK, "d.sock")).encode()
    s.sendall(bytes([0x05, 0x01, 0x00, 0x03, len(host)]) + host
              + struct.pack(">H", 1))
    rep = s.recv(4)
    dt = time.time() - t0
    print("reply=%r after %.1fs" % (rep, dt))
    assert rep[0] == 0x05 and rep[1] != 0x00, "expected a SOCKS refusal"
    assert dt < 25, "refusal took too long (wait is 20s)"
    print("socks-wait-probe: silent node refused in %.1fs, code %d"
          % (dt, rep[1]))
finally:
    relay.terminate()
    relay.wait()
