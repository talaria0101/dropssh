#!/usr/bin/env python3
"""case3-loop: run mux-probe case 3 (text frame on data leg) N times.

Reuses tests/mux-probe.py helpers. Asserts the node socket closes 1003.
Prints the flake rate. Usage: case3-loop.py DROPSHH_BIN WORKDIR N
"""
import importlib.util
import os
import subprocess
import sys
import time

N = int(sys.argv[3]) if len(sys.argv) > 3 else 100
DROPSHH = sys.argv[1]
WORK = sys.argv[2]
os.makedirs(WORK, exist_ok=True)

spec = importlib.util.spec_from_file_location(
    "muxprobe", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "mux-probe.py"))
mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mux)

sock_path = os.path.join(WORK, "case3-%d.sock" % os.getpid())
relay_log = open(os.path.join(WORK, "case3-relay.log"), "wb")
relay = subprocess.Popen(
    [DROPSHH, "relay", "--listen", "unix://" + sock_path],
    stdout=subprocess.DEVNULL, stderr=relay_log)
try:
    for _ in range(200):
        if os.path.exists(sock_path):
            break
        time.sleep(0.05)
    assert os.path.exists(sock_path), "relay never bound"

    bad = 0
    codes = {}
    for i in range(N):
        # Reuse 4 names: the relay holds at most 32 names, so a fresh name
        # per iter would exhaust the table at 32 and measure the cap.
        try:
            s = mux.run_case(sock_path, "c3-%d" % (i % 4),
                             node_sends_id_prefix=True, node_text=True)
        except Exception as e:
            bad += 1
            print("iter %d: harness error %r" % (i, e))
            continue
        if s.node_close is None:
            bad += 1
            print("iter %d: NO close on node socket" % i)
        else:
            code, reason = s.node_close
            codes[code] = codes.get(code, 0) + 1
            if code != 1003:
                bad += 1
                print("iter %d: node close %d %r (want 1003)" % (i, code, reason))
        try:
            s.node.close()
        except Exception:
            pass
        try:
            s.op.close()
        except Exception:
            pass
    print("case3-loop: %d/%d bad (flake rate %.1f%%), codes=%s"
          % (bad, N, 100.0 * bad / N, codes))
    sys.exit(1 if bad else 0)
finally:
    relay.terminate()
    relay.wait()
