#!/usr/bin/env python3
"""mux-probe.py - assert the relay's id-prefix rule, and its close codes.

This is R1 and R11 from docs/relay-issues.md, and it is a gate rather than a
document because the failure it covers is one that looks like something else.
A node that sends a data frame without its 32-hex session id has its frames
DISCARDED by the relay, the operator receives nothing, no error appears, and
the session goes quiet. That is indistinguishable from a relay that is down.

Measured against tcp.ssh.relay.ajam.dev on 2026-09-28, 3/3 runs, and that
measurement is what this file encodes:

    node sends <id><payload>  -> operator receives <payload>          correct
    node sends <payload>       -> node closed 1009 "bad multiplex frame"
                                 operator then closed 1011 "node disconnected"
    operator sends "SOME TEXT" -> operator closed 1003 "binary frames required"

Note the asymmetry the first two lines describe, because it is the single most
surprising thing about the protocol: the OPERATOR writes bare bytes and the
relay prepends the id for the node, while the NODE prefixes the id and the
relay strips it. Both peers would be wrong in the same way and the two errors
look identical from the outside.

USAGE: mux-probe.py DROPSSH_BINARY WORKDIR
  Starts `dropssh relay` on a unix socket in WORKDIR, drives one node and one
  operator against it, and exits non-zero if any rule above is broken.
"""
import base64
import hashlib
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ID_LEN = 32


# ----------------------------------------------------------------- framing
def encode_frame(opcode, payload, mask):
    b = bytes([0x80 | opcode])
    n = len(payload)
    mb = 0x80 if mask else 0
    if n < 126:
        b += bytes([mb | n])
    elif n < 65536:
        b += bytes([mb | 126]) + struct.pack(">H", n)
    else:
        b += bytes([mb | 127]) + struct.pack(">Q", n)
    if mask:
        # RFC 6455 requires a client to mask, and a spec-following server
        # closes a connection that does not. The key is fixed here because this
        # is a test and a predictable key is easier to read in a packet dump
        # than a random one; nothing in the protocol depends on it varying.
        k = b"\x01\x02\x03\x04"
        b += k + bytes(c ^ k[i % 4] for i, c in enumerate(payload))
    else:
        b += payload
    return b


class Reader:
    """Decodes websocket frames off a socket, keeping the opcode with its own
    frame. A byte-stream reader cannot do this, and the whole protocol depends
    on it: a control message is a TEXT frame and session data is a BINARY one,
    and a decoder that reports "the last opcode" for everything in a coalesced
    read makes a control message out of session bytes."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def feed(self, timeout):
        self.sock.settimeout(timeout)
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            return True
        except OSError:
            return False
        if not chunk:
            return False
        self.buf += chunk
        return True

    def take(self):
        """(opcode, payload) for the next complete frame, or None."""
        if len(self.buf) < 2:
            return None
        op = self.buf[0] & 0x0F
        masked = self.buf[1] & 0x80
        n = self.buf[1] & 0x7F
        off = 2
        if n == 126:
            if len(self.buf) < 4:
                return None
            n = struct.unpack(">H", self.buf[2:4])[0]
            off = 4
        elif n == 127:
            if len(self.buf) < 10:
                return None
            n = struct.unpack(">Q", self.buf[2:10])[0]
            off = 10
        if masked:
            off += 4
        if len(self.buf) < off + n:
            return None
        payload = self.buf[off:off + n]
        self.buf = self.buf[off + n:]
        return op, payload


def connect_relay(path):
    """A unix socket to the relay, connected. The path is the socket FILE, not
    a dropssh --relay value, so the 'unix://' prefix is stripped here rather
    than three times at each call site."""
    p = path[len("unix://"):] if path.startswith("unix://") else path
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(p)
    return s


def handshake(sock, path):
    key = base64.b64encode(b"0123456789abcdef").decode()
    req = (
        "GET %s HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n" % (path, key)
    ).encode()
    sock.sendall(req)
    buf = b""
    sock.settimeout(15)
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("relay closed the connection during the upgrade")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n")[0]
    code = int(status.split()[1])
    if code != 101:
        raise RuntimeError("upgrade refused: %s" % status.decode())
    # The Sec-WebSocket-Accept is checked rather than assumed. A server that
    # answers 101 without the right accept value is not a websocket peer, and
    # every frame after that would be interpreted against the wrong rules.
    want = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
    if want.encode() not in head:
        raise RuntimeError("the relay's Sec-WebSocket-Accept did not match the key sent")
    return rest


def close_of(payload):
    if len(payload) >= 2:
        return struct.unpack(">H", payload[:2])[0], payload[2:].decode("utf-8", "replace")
    return 1005, ""


# ------------------------------------------------------------------- cases
class Session:
    """One node and one operator on a relay, with the id the relay chose."""

    def __init__(self, node, op, node_buf, session_id, reader_node):
        self.node = node
        self.op = op
        self.node_buf = node_buf
        self.rn = reader_node
        self.ro = Reader(op)
        self.id = session_id
        self.closed_by = None   # (side, code, reason) - the FIRST close seen
        self.node_close = None   # the node socket's own close, the diagnosis
        self.op_close = None
        self.op_text = []
        self.op_bin = []
        self.node_bin = []
        self.node_text = []


def run_case(relay_path, name, node_sends_id_prefix, node_text=False):
    """One pair. Returns the Session with everything both sides observed."""
    node = connect_relay(relay_path)
    node.settimeout(15)
    node_buf = handshake(node, "/v1/node/%s" % name)
    rn = Reader(node)
    rn.buf = node_buf

    hello = None
    deadline = time.time() + 5
    while time.time() < deadline and hello is None:
        if not rn.feed(0.3):
            break
        f = rn.take()
        if f and f[0] == 0x1:
            m = parse_json(f[1])
            if m.get("type") == "hello":
                hello = m
    if hello is None:
        node.close()
        raise RuntimeError("the relay sent no hello within 5s")

    op = connect_relay(relay_path)
    op.settimeout(15)
    op_buf = handshake(op, "/v1/connect/%s" % name)
    ro = Reader(op)
    ro.buf = op_buf

    # The open and the id the relay minted.
    session_id = None
    deadline = time.time() + 8
    while time.time() < deadline and session_id is None:
        if not rn.feed(0.3):
            break
        f = rn.take()
        if f and f[0] == 0x1:
            m = parse_json(f[1])
            if m.get("type") == "open":
                session_id = m.get("id")
    if not session_id:
        op.close()
        node.close()
        raise RuntimeError("the relay sent no open within 8s")

    s = Session(node, op, node_buf, session_id, rn)
    s.hello = hello

    # ⛔ THE OPERATOR SENDS NO CONTROL FRAME AT ALL, AND THAT IS MEASURED
    # AGAINST tcp.ssh.relay.ajam.dev, NOT ASSUMED. The relay's own reference
    # operator (docs/08-reverse.md) sends `{"type":"ready"}` as a text frame
    # from the operator, and doing that here is closed with 1003 "binary frames
    # required": the operator's leg is a data leg and a text frame on it is a
    # protocol error. Measured live 2026-09-28, 2/2, for both a `ready` and an
    # arbitrary text payload.
    #
    # So an operator speaks only binary on this link. The node answers `open`
    # with `ready`, the relay forwards that to the operator as text, and the
    # operator's job is to have already sent its banner. The asymmetry is the
    # point: the node speaks control both ways and the operator speaks data
    # only.
    time.sleep(0.4)

    if node_text:
        # A TEXT frame where the relay expects data.
        s.node.sendall(encode_frame(0x1, b"this should be data", True))
    elif node_sends_id_prefix:
        s.node.sendall(encode_frame(0x2, session_id.encode() + b"PREFIXED-PAYLOAD", True))
    else:
        # A BARE payload: the exact mistake B2 and B11 describe.
        s.node.sendall(encode_frame(0x2, b"BARE-PAYLOAD", True))

    # The operator writes BARE bytes; the relay prepends the id for the node.
    s.op.sendall(encode_frame(0x2, b"OP-BARE", True))

    drain(s, 3.0)
    return s


def json_bytes(obj):
    import json
    return json.dumps(obj, separators=(",", ":")).encode()


def parse_json(b):
    import json
    try:
        return json.loads(b.decode("utf-8", "replace"))
    except Exception:
        return {}


def drain(s, seconds):
    """Read both sides until the window closes, recording every close code.

    ⛔ BOTH CLOSES ARE COLLECTED, NOT JUST THE FIRST. The relay closes the
    NODE with the diagnosis (1009 or 1003) and then closes the OPERATOR with
    1011 as a consequence, and the two arrive in either order depending on
    timing. A reader that stopped at the first close saw only 1011 on a good
    relay and called it a failure, and a reader that only ever looked at the
    operator's close could not tell a framing fault from the node being gone.
    So each socket is read to its own end and each close is attributed to the
    socket that sent it."""
    end = time.time() + seconds
    while time.time() < end:
        for side, reader, texts, bins in (
            ("node", s.rn, s.node_text, s.node_bin),
            ("op", s.ro, s.op_text, s.op_bin),
        ):
            reader.feed(0.1)
            while True:
                f = reader.take()
                if f is None:
                    break
                op, payload = f
                if op == 0x8:
                    code, reason = close_of(payload)
                    if side == "node":
                        s.node_close = (code, reason)
                        if s.closed_by is None:
                            s.closed_by = (side, code, reason)
                    else:
                        s.op_close = (code, reason)
                        if s.closed_by is None:
                            s.closed_by = (side, code, reason)
                elif op == 0x1:
                    texts.append(parse_json(payload))
                elif op == 0x2:
                    bins.append(payload)


# -------------------------------------------------------------------- main
def main():
    if len(sys.argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    dropssh, work = sys.argv[1], sys.argv[2]
    # ⛔ THE PROBE'S SOCKET PATH IS UNIQUE PER RUN, AND THE REASON IS THAT THE
    # RELAY DOES `unlink` THEN `bind` ON A FIXED PATH. Two runs of the probe --
    # or a probe racing a relay left over from an interrupted suite -- both
    # unlink the same path, and the second bind either steals the first
    # relay's socket or fails against a file another process is holding. The
    # failure mode is a ConnectionRefused in an unrelated test, which names the
    # wrong thing entirely.
    sock_path = os.path.join(
        work, "muxprobe-%d-%d.sock" % (os.getpid(), int(time.time() * 1000) % 100000))

    relay_log = open(os.path.join(work, "muxprobe-relay.log"), "wb")
    relay = subprocess.Popen(
        [dropssh, "relay", "--listen", "unix://" + sock_path],
        stdout=subprocess.DEVNULL, stderr=relay_log,
    )
    try:
        for _ in range(200):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        if not os.path.exists(sock_path):
            print("mux-probe: the relay never bound %s" % sock_path)
            return 1

        failures = []

        # ---- case 1: the node prefixes the id, and the operator gets the
        # payload BARE. This is the happy path and it is the one that a bug in
        # the strip step turns into 32 hex characters in front of every ssh
        # packet.
        try:
            s = run_case(sock_path, "case1", node_sends_id_prefix=True)
        except (BrokenPipeError, ConnectionResetError) as e:
            # ⛔ A RESET IS A FAILURE WITH A NAME, NOT A TRACEBACK. A relay
            # that forwards the id it should have stripped, or that closes on
            # the first data frame, shows up here as a broken pipe; letting it
            # escape prints a Python stack and says nothing about which rule
            # broke, which is the same "a failure that names the wrong thing"
            # the e2e has been bitten by twice.
            print("mux-probe: FAIL the pair was torn down before the first "
                  "exchange completed (%s). The node and operator legs did not "
                  "both survive a hello, an open and one data frame." % e)
            return 1
        got = b"".join(s.op_bin)
        if got != b"PREFIXED-PAYLOAD":
            failures.append(
                "a node frame with its 32-hex id did not reach the operator as the "
                "bare payload; the operator received %r" % got)
        # ... and the operator's bare bytes reached the node with the id on.
        nbin = b"".join(s.node_bin)
        if not nbin.startswith(s.id.encode()) or not nbin.endswith(b"OP-BARE"):
            failures.append(
                "the operator's bare bytes did not reach the node as id+payload; "
                "the node received %r (id %s)" % (nbin[:48], s.id))
        elif nbin[len(s.id):] != b"OP-BARE":
            failures.append(
                "the node received extra bytes before the operator's payload: %r"
                % nbin[:len(s.id) + 24])
        s.node.close()
        s.op.close()

        # ---- case 2: the node sends a BARE frame. The relay must close the
        # NODE with a NAMED close, and must not let the operator see the
        # payload. The old documentation said this was silent; measured live on
        # 2026-09-28 it is code 1009 "bad multiplex frame", and then 1011 on
        # the operator. A relay that drops it quietly is the bug.
        try:
            s = run_case(sock_path, "case2", node_sends_id_prefix=False)
        except (BrokenPipeError, ConnectionResetError) as e:
            failures.append("the pair was torn down before case %s completed (%s)" % ("case2", e))
            return 1
        # ⛔ THE NODE'S CLOSE IS THE ONE THAT NAMES THE FAULT. The operator's
        # socket is closed 1011 "node disconnected" as a consequence, and that
        # is the code an operator sees; but 1011 says nothing about WHY. The
        # node's own socket carries 1009 "bad multiplex frame", which is the
        # diagnosis, and it is the close this case asserts. Both are recorded;
        # only the node's is required.
        if s.node_close is None:
            failures.append(
                "a bare node frame produced NO close on the node socket: the "
                "session went quiet, which is the B11 failure mode this case "
                "exists to catch")
        else:
            code, reason = s.node_close
            if code != 1009:
                failures.append(
                    "a bare node frame closed the NODE with %d %r, expected 1009 "
                    "'bad multiplex frame'" % (code, reason))
        if b"BARE-PAYLOAD" in b"".join(s.op_bin):
            failures.append(
                "a bare node frame's payload reached the operator; the relay must "
                "not forward a frame it cannot attribute")
        s.node.close()
        s.op.close()

        # ---- case 3: a TEXT frame where data was required. The measured close
        # is 1003 "binary frames required" on the operator, and it is a
        # DIFFERENT code from case 2, so the two are logged distinctly rather
        # than collapsed into "framing error".
        try:
            s = run_case(sock_path, "case3", node_sends_id_prefix=True, node_text=True)
        except (BrokenPipeError, ConnectionResetError) as e:
            failures.append("the pair was torn down before case %s completed (%s)" % ("case3", e))
            return 1
        if s.node_close is None:
            failures.append(
                "a text frame on the data leg produced no close on the node socket")
        else:
            code, reason = s.node_close
            if code != 1003:
                failures.append(
                    "a text frame on the data leg closed the NODE with %d %r, "
                    "expected 1003 'binary frames required'" % (code, reason))
        s.node.close()
        s.op.close()

        for f in failures:
            print("mux-probe: FAIL %s" % f)
        if not failures:
            print("mux-probe: id-prefix, bare-frame close 1009, and text-frame "
                  "close 1003 all behave as measured")
        return 1 if failures else 0
    finally:
        relay.terminate()
        try:
            relay.wait(timeout=5)
        except subprocess.TimeoutExpired:
            relay.kill()


if __name__ == "__main__":
    sys.exit(main())
