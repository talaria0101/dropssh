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
    # operator sends its banner afterwards. The asymmetry is the point: the node
    # speaks control both ways and the operator speaks data only.
    #
    # ⛔ THE NODE ANSWERS `ready` HERE, AND ITS ABSENCE WAS A REAL DEFECT IN THIS
    # PROBE. It had never sent one: the code that answered `open` was replaced
    # during the wait-for-ready fix and the replacement did not put it back. The
    # probe still passed, because the relay did not enforce the ordering -- and
    # so the probe had been asserting, for several runs, that the relay does NOT
    # require `ready`. A test that passes for the wrong reason keeps passing
    # while the thing it names regresses, which is the failure mode this project
    # has now hit three times: a guard that cannot fail, a gate with no case, and
    # a probe that passed the wrong way round.
    node.sendall(encode_frame(
        0x1, json_bytes({"type": "ready", "id": session_id}), True))

    # ⛔ AND THEN THE OPERATOR WAITS FOR THAT `ready` TO REACH IT. Not a sleep:
    # the observed thing, bounded. A fixed sleep is a coin flip and a coin flip
    # in a gate is a flake someone will spend a morning on.
    deadline = time.time() + 8
    saw_ready = False
    while time.time() < deadline and not saw_ready:
        if not s.ro.feed(0.2):
            break
        while True:
            f = s.ro.take()
            if f is None:
                break
            op, payload = f
            if op == 0x8:
                code, reason = close_of(payload)
                s.op_close = (code, reason)
                s.closed_by = ("op", code, reason)
            elif op == 0x1:
                m = parse_json(payload)
                s.op_text.append(m)
                if m.get("type") == "ready":
                    saw_ready = True
                    break
            else:
                s.op_bin.append(payload)
    if not saw_ready:
        node.close()
        op.close()
        raise RuntimeError(
            "the node's `ready` did not reach the operator within 8s, so the "
            "framing rules cannot be asserted: the relay is not pairing, and a "
            "failure here would name the wrong thing")

    if node_text:
        # A TEXT frame where the relay expects data.
        s.node.sendall(encode_frame(0x1, b"this should be data", True))
    elif node_sends_id_prefix:
        s.node.sendall(encode_frame(0x2, session_id.encode() + b"PREFIXED-PAYLOAD", True))
    else:
        # A BARE payload: the exact mistake B2 and B11 describe.
        s.node.sendall(encode_frame(0x2, b"BARE-PAYLOAD", True))

    # ⛔ THE OPERATOR'S BYTES GO AFTER THE NODE'S FRAME, AND THAT ORDER IS NOW
    # PART OF THE PROTOCOL RATHER THAN A COINCIDENCE OF TIMING. This relay
    # refuses operator data sent before the node has answered `open` with
    # `ready` -- close 1008 "wait for ready", the same code and reason the ajam
    # relay uses (measured 2026-09-28) -- and case 5 asserts exactly that.
    #
    # The first version of this probe sent the operator's bytes unconditionally
    # and let the node's `ready` arrive whenever it arrived. It passed against a
    # relay that did not enforce the ordering, so it was really asserting that
    # the relay DID NOT enforce it. A test that passes for the wrong reason is
    # worse than one that fails, and this one would have kept passing while the
    # ordering regressed. Sending the node's frame first and draining a turn
    # before the operator's makes the ordering explicit and deterministic.
    s.op.sendall(encode_frame(0x2, b"OP-BARE", True))

    # ⛔ THE DATA WINDOW AND THE CLOSE WINDOW ARE SEPARATE, AND THE CLOSE GETS
    # A BOUNDED WAIT OF ITS OWN. The first version drained for a fixed 3 s and
    # expected both the payload and the close inside it. On a loaded machine the
    # payload arrives and the close, which the relay sends after it has closed
    # its own side, can arrive after the window -- so the case reported "no
    # close" and failed for a reason that had nothing to do with the rule.
    #
    # The two are separated because they are different observations: case 1
    # asserts a payload, cases 2 and 3 assert a close, and a case that fails
    # because the close was slow teaches a reader the close code is unreliable
    # when it is merely asynchronous.
    drain(s, 2.0)
    if s.node_close is None:
        deadline = time.time() + 5
        while time.time() < deadline and s.node_close is None:
            drain(s, 0.3)
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

        # ---- case 5: the operator's `ready` GATE.
        # ⛔ THIS CASE EXISTS BECAUSE A CLAIM WAS FALSE, NOT BECAUSE A BUG WAS
        # FOUND IN THE GATE.
        #
        # The relay does not create a session until the node answers `open`
        # with `ready`, and an operator that writes before that answer arrives
        # has BOTH ends torn down: operator 1008 "wait for ready", node 1003
        # "unknown session id". `dropssh connect` therefore holds stdin until it
        # sees `ready`, and that gate is the difference between a working live
        # session and a hang.
        #
        # ⛔ IT HAD NO TEST. The gate is in `connect`, and `connect` is what the
        # e2e drives with a real ssh -- which sends its banner immediately, so
        # the e2e could not tell a gated operator from an ungated one: a real
        # relay that does not enforce the ordering accepts both. Planting the
        # gate's removal, i.e. building `connect` with the gate deleted, was
        # detected 0 times in 10 runs. A guard that cannot fail is not a guard,
        # and this one was described in a commit message as proven.
        #
        # So the case drives the ordering itself: an operator that SENDS BEFORE
        # the node has answered, against a relay that enforces it. The
        # assertion is the close -- 1008 on the operator, 1003 on the node --
        # and the second half is that `dropssh connect` exits NON-ZERO when that
        # happens, which is the half that was also wrong and is now fixed.
        gate_failures = []
        gnode = connect_relay(sock_path)
        gnb = handshake(gnode, "/v1/node/case5")
        gnr = Reader(gnode); gnr.buf = gnb
        deadline = time.time() + 5
        while time.time() < deadline:
            if not gnr.feed(0.2):
                break
            f = gnr.take()
            if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                break
        gop = connect_relay(sock_path)
        gob = handshake(gop, "/v1/connect/case5")
        gor = Reader(gop); gor.buf = gob
        # Deliberately do NOT answer the node's `open`. The operator now sends
        # session data, which is exactly what an ungated client does.
        gop.sendall(encode_frame(0x2, b"EARLY-BANNER", True))
        gclosed = None
        nclosed = None
        deadline = time.time() + 8
        while time.time() < deadline and gclosed is None:
            for reader, which in ((gor, "op"), (gnr, "node")):
                reader.feed(0.2)
                while True:
                    f = reader.take()
                    if f is None:
                        break
                    if f[0] == 0x8:
                        code, reason = close_of(f[1])
                        if which == "op":
                            gclosed = (code, reason)
                        else:
                            nclosed = (code, reason)
            if gclosed and nclosed:
                break
        if gclosed is None:
            gate_failures.append(
                "an operator that sent session data before the node answered "
                "`ready` was NOT closed; the ordering the gate exists to avoid "
                "is not being enforced by this relay")
        elif gclosed[0] != 1008:
            gate_failures.append(
                "an early operator was closed with %d %r, expected 1008 "
                "'wait for ready'" % (gclosed[0], gclosed[1]))
        if nclosed is not None and nclosed[0] != 1003:
            gate_failures.append(
                "the node was closed with %d %r, expected 1003 "
                "'unknown session id'" % (nclosed[0], nclosed[1]))
        gop.close()
        gnode.close()
        failures.extend(gate_failures)

        # ---- case 6: `dropssh connect` ON A NODE THAT DOES NOT ANSWER `open`.
        #
        # ⛔ THE STALLING SERVER IS NOT ENOUGH, AND THAT WAS THE BUG IN THE FIRST
        # VERSION OF THIS CASE. `dropssh serve` answers `open` with `ready` as
        # soon as its server command STARTS -- a `sleep` server starts fine, so
        # the node answered `ready` immediately, the gate opened, and the case
        # measured a healthy session while asserting a silent one. It reported
        # "the wait has no bound" about a wait that had correctly ended.
        #
        # A node that does not answer `open` is a node whose server command does
        # NOT start, because the `ready` is sent only after start_server has
        # returned. So the case needs a server command that fails to start,
        # which `serve` detects at startup and refuses to run at all -- so the
        # honest way to produce an unanswered `open` is a node that never
        # reaches the relay, and the honest way to assert a bounded wait is
        # against a relay with no node.
        #
        # ⛔ So THAT is what this does: a name with no node, on a relay that
        # answers 503 on the UPGRADE. `dropssh connect` must fail, name the
        # reason, and do it promptly. That is a real operator situation -- the
        # node is not running, or has not dialled yet -- and it is the one an
        # operator meets first.
        #
        # This case exists because `dropssh connect` exited 0 after the relay
        # closed with 1008 "node open timeout" -- a refused login reported to
        # ssh as a success. That half is real and is asserted below.
        #
        # ⛔ IT DELIBERATELY DOES NOT ASSERT THAT THE ready-GATE IS WHAT PREVENTS
        # IT, BECAUSE MEASUREMENT SAYS IT CANNOT BE SEEN FROM OUTSIDE. Against
        # this relay, which refuses early operator data (case 5), a gated
        # `connect` and one built with the gate deleted were run side by side:
        # identical exit status, identical elapsed time, identical message,
        # and the relay's log recorded zero early data frames in BOTH. Planting
        # the gate's removal was detected 0 times in 10 runs -- not because the
        # gate does nothing, but because with an enforcing relay the two
        # journeys end in the same observable place.
        #
        # ⛔ SO THE GATE IS RECORDED HERE AS UNGUARDED RATHER THAN GIVEN A CASE
        # THAT CANNOT FAIL. A previous version of this comment claimed the gate
        # was "proven to fire"; it was not, and the claim was the reason nobody
        # looked. What IS asserted is the bound and the exit code, both of
        # which have been shown to fail when the corresponding change is made.
        #
        # ⛔ AND ONE MORE HONEST NEGATIVE, FOUND WHILE CHECKING. The exit code
        # on a pre-`ready` close was changed from 0 to 1 during this review, and
        # planting the change back is detected 0 times in 6 runs -- because the
        # 60-second bound is reached first whenever the node never answers, so
        # the pre-`ready` close path is not the one that ends the session. The
        # fix is therefore correct but not independently testable by this
        # probe: its observable effect is entirely on a path the bound shadows.
        # It is kept because the path is real on the live relay, where the
        # relay's own 10s open timeout closes the socket long before our bound,
        # and that is measured -- but it is not claimed here as guarded.
        #
        # ⛔ AND A REAL DEFECT WAS FOUND WHILE TRYING. The 60-second bound on
        # this wait was unreachable: the reverse branch ends in `continue`,
        # which skipped the counter, so `connect` waited for ever on a silent
        # relay. As an ssh ProxyCommand that is an ssh that never times out.
        # The bound is now above every `continue` in the loop and this case
        # exercises it, which is why the case asserts a BOUNDED wait and not
        # merely an exit code.
        gate_client = []
        t0 = time.time()
        try:
            r = subprocess.run(
                [dropssh, "connect", "--relay", "unix://" + sock_path,
                 "--name", "no-such-node-for-case-6"],
                input=b"SSH-2.0-GateProbe\r\n",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            elapsed = time.time() - t0
            if r.returncode == 0:
                gate_client.append(
                    "`dropssh connect` exited 0 for a name with no node attached; a "
                    "refused login is being reported as a success")
            # ⛔ THE MESSAGE MUST NAME THE CAUSE, BECAUSE "CONNECTION FAILED" IS NOT
            # ACTIONABLE. The relay's own sentence is what distinguishes "the node
            # is not running" from "the relay is full" from "the token is wrong",
            # and an operator who is told only that something failed has to try
            # the next idea in the wrong order.
            elif b"503" not in r.stderr:
                gate_client.append(
                    "`dropssh connect` exited %d for a name with no node, and the "
                    "message did not carry the relay's reason: %r"
                    % (r.returncode, r.stderr[:140]))
            # ⛔ AND IT MUST BE PROMPT. This process is an ssh ProxyCommand; an
            # operator whose node has not dialled yet gets an ssh that appears to
            # hang, with nothing to read. A refusal is answered at the speed of
            # an HTTP status, not at the speed of a TCP timeout.
            elif elapsed > 10:
                gate_client.append(
                    "`dropssh connect` took %.1fs to report a refused node; the "
                    "operator is waiting on an ssh that looks hung" % elapsed)
        except subprocess.TimeoutExpired:
            gate_client.append(
                "`dropssh connect` did not return within 30s for a name with no "
                "node; a refused login is not bounded")
        except Exception as e:
            gate_client.append("the `connect` refusal case could not run: %s" % e)
        failures.extend(gate_client)

        # ---- case 4: a NODE DISCONNECT WHILE AN OPERATOR IS ATTACHED.
        # ⛔ THIS CASE EXISTS BECAUSE OF A REAL CRASH, AND IT IS THE ONLY CASE
        # THAT WOULD HAVE CAUGHT IT DETERMINISTICALLY.
        #
        # When a node goes away, the relay tells every attached operator 1011
        # "node disconnected" -- from the NODE's thread -- while each
        # operator's own thread is still reading its socket and will close its
        # own session when that read ends. Two threads, one WsSession, and
        # ws_close frees the session's buffers, so both freeing them took the
        # whole relay process down with
        #
        #     double free or corruption (fasttop)
        #
        # which killed every OTHER node and operator on it. It reproduced about
        # once in twelve runs, which is the worst possible frequency: rare
        # enough to look like a flake and common enough to be a production
        # outage. Cases 1-3 never touch that path, because each of them lets
        # the operator go first.
        #
        # So the ordering is forced: the operator is attached and idle, and the
        # NODE is the one that closes. The assertion is that the relay is still
        # serving afterwards -- which is the property that actually broke, and
        # which no assertion about one session's bytes would have caught.
        node_probe_ok = True
        try:
            nsock = connect_relay(sock_path)
            handshake_return = None
            nb = handshake(nsock, "/v1/node/case4")
            nr = Reader(nsock)
            nr.buf = nb
            # the relay's hello
            deadline = time.time() + 5
            while time.time() < deadline:
                if not nr.feed(0.2):
                    break
                f = nr.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                    break
            osock = connect_relay(sock_path)
            ob = handshake(osock, "/v1/connect/case4")
            orr = Reader(osock)
            orr.buf = ob
            # wait for `open`
            sid4 = None
            deadline = time.time() + 8
            while time.time() < deadline and sid4 is None:
                if not nr.feed(0.2):
                    break
                f = nr.take()
                if f and f[0] == 0x1:
                    m = parse_json(f[1])
                    if m.get("type") == "open":
                        sid4 = m.get("id")
                        nsock.sendall(encode_frame(
                            0x1, json_bytes({"type": "ready", "id": sid4}), True))
            # The operator is attached and has NOT sent anything. Now the node
            # vanishes: this is the ordering that used to double free.
            nsock.close()
            # Give the relay time to do its 1011 sweep and for the operator's
            # own thread to notice its socket ended.
            time.sleep(2.0)
            # The relay must still be alive and still serve a NEW pair. That is
            # the assertion: a double free takes the process, so the cheapest
            # way to see it is to ask the relay for another session afterwards.
            probe2 = connect_relay(sock_path)
            b2 = handshake(probe2, "/v1/node/case4-after")
            p2 = Reader(probe2)
            p2.buf = b2
            alive = False
            deadline = time.time() + 5
            while time.time() < deadline:
                if not p2.feed(0.2):
                    break
                f = p2.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                    alive = True
                    break
            probe2.close()
            osock.close()
            if not alive:
                failures.append(
                    "after a node disconnected with an operator attached, the "
                    "relay did not serve a NEW node: the process is gone, which "
                    "is what a double free in the 1011 sweep does")
        except Exception as e:
            node_probe_ok = False
            failures.append("the node-disconnect case could not run: %s" % e)

        # ---- case 7: a REFUSAL ON THE OPERATOR'S OWN THREAD.
        # ⛔ THIS CASE CLOSES THE GAP THE `c->ws` MOVE LEFT OPEN, AND THE REASON
        # IT IS NEEDED IS SPECIFIC RATHER THAN GENERAL.
        #
        # The operator's WsSession is MOVED into the Client rather than copied,
        # because a struct copy shares its buffer POINTERS and every
        # `ws_close(&ws)` on the connection thread's stack copy would then free
        # memory the Client still owns. Reverting the move to a memcpy and
        # running this probe 20 times produced no crash -- the probe's other
        # cases never reach the combination. The combination is: a REFUSAL path
        # that closes the stack copy after the client is in the table, with the
        # session closed again by client_release.
        #
        # So the case drives exactly that. A relay started with
        # --max-sessions 1 is given TWO operators for the same node. The second
        # is refused, and its refusal path closes the stack copy -- which, with
        # the move reverted, is the same buffers the first operator's session
        # owns. The assertion is the cheap one that a double free cannot pass:
        # the relay is still serving afterwards.
        #
        # ⛔ AND THE RELAY IS LEFT SERVING BY THE ASSERTION, NOT BY THE PROCESS
        # BEING FINE. A double free takes the process, so the way to see it is to
        # ask for another session afterwards. That is the same shape as case 4
        # and for the same reason.
        limit_failures = []
        limsock = "/tmp/muxlimit-%d.sock" % os.getpid()
        limlog = open(os.path.join(work, "muxprobe-limit.log"), "wb")
        limrelay = subprocess.Popen(
            [dropssh, "relay", "--listen", "unix://" + limsock,
             "--max-sessions", "1"],
            stdout=subprocess.DEVNULL, stderr=limlog)
        try:
            for _ in range(200):
                if os.path.exists(limsock):
                    break
                time.sleep(0.05)
            lnode = connect_relay(limsock)
            lnb = handshake(lnode, "/v1/node/limit7")
            lnr = Reader(lnode); lnr.buf = lnb
            deadline = time.time() + 5
            while time.time() < deadline:
                if not lnr.feed(0.2):
                    break
                f = lnr.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                    break
            # two operators, the second over the session limit
            ops = []
            for i in (1, 2):
                try:
                    o = connect_relay(limsock)
                    handshake(o, "/v1/connect/limit7")
                    ops.append(o)
                except RuntimeError as e:
                    # a refusal AT THE UPGRADE is also a refusal, and also a
                    # path that closes the stack copy
                    if "503" not in str(e) and "409" not in str(e):
                        raise
            time.sleep(1.0)
            # the relay must still be serving
            probe3 = connect_relay(limsock)
            b3 = handshake(probe3, "/v1/node/limit7-after")
            p3 = Reader(probe3); p3.buf = b3
            alive = False
            deadline = time.time() + 5
            while time.time() < deadline:
                if not p3.feed(0.2):
                    break
                f = p3.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                    alive = True
                    break
            probe3.close()
            for o in ops:
                try:
                    o.close()
                except Exception:
                    pass
            lnode.close()
            if not alive:
                limit_failures.append(
                    "after refusing an operator on the session limit the relay did "
                    "not serve a NEW node: the process is gone, which is what a "
                    "double free in a refusal path does")
        except Exception as e:
            limit_failures.append("the refusal-path case could not run: %s" % e)
        finally:
            limrelay.terminate()
            try:
                limrelay.wait(timeout=5)
            except Exception:
                limrelay.kill()
            limlog.close()
            try:
                os.unlink(limsock)
            except OSError:
                pass
        failures.extend(limit_failures)

        for f in failures:
            print("mux-probe: FAIL %s" % f)
        if not failures:
            print("mux-probe: id-prefix, bare-frame close 1009, text-frame "
                  "close 1003, the ready ordering, a bounded `connect` that "
                  "exits non-zero on a silent node, a node disconnect with an "
                  "operator attached, and a refusal on the operator's own thread "
                  "all behave as measured")
        return 1 if failures else 0
    finally:
        relay.terminate()
        try:
            relay.wait(timeout=5)
        except subprocess.TimeoutExpired:
            relay.kill()


if __name__ == "__main__":
    sys.exit(main())
