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

It also starts a RELAY STUB (`SilentNodeRelay`, U1 in docs/relay-issues.md):
one that completes a websocket upgrade for the operator and then says nothing at
all. That is the only way to reach the 60-second bound in src/connect.c, and it
is the reason the bound was unguarded rather than unproven.
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
import threading
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


def run_case(relay_path, name, node_sends_id_prefix, node_text=False,
            expect_node_close=False):
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
    # The operator's bytes go after the node's frame, except when the case
    # expects the node to be CLOSED for that frame (bare id, text on a data
    # leg). Sending them anyway races the close: the relay may forward the
    # bytes first and the probe then parses a DATA frame as the close it is
    # waiting for -- a garbage code like 33319 -- and reports a relay bug
    # that is really probe timing. Measured on CI 2026-09-30. A case that
    # expects a close sends nothing after the fault.
    if not expect_node_close:
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


class SilentNodeRelay(threading.Thread):
    """A relay that upgrades the operator and then says NOTHING FOR EVER.

    ⛔ THIS IS THE STUB THAT MAKES U1 CLOSEABLE, AND IT EXISTS BECAUSE THE
    REAL RELAY CANNOT REACH THE CODE UNDER TEST.

    `docs/relay-issues.md` U1: the 60-second bound on the wait for the node's
    `ready`, in `src/connect.c`, was 0/6 on the plant. The stated reason is that
    this relay answers **503 on the upgrade** for a name with no node, so the
    bound is never reached -- the session dies before the wait starts. That is
    true, and it means the bound is unreachable by changing the client. It is
    reachable by changing the RELAY: a relay that accepts the upgrade, tells the
    operator nothing, and never closes is exactly the "relay that never closes"
    the bound was written for, and it is the one the comment in connect.c names
    as the reason the bound exists.

    ⛔ SO THE STUB IMPLEMENTS THE PROTOCOL, NOT JUST THE SILENCE. A stub that
    only completed the upgrade would test a different thing: the operator would
    be sitting on a socket that is not a relay at all, and a bound that fired
    there would say nothing about a bound firing on one. So this speaks the real
    reverse protocol: it sends `hello`, it mints a session id and sends `open`,
    and it simply never forwards a `ready`. `dropssh connect` is therefore
    waiting on a node that never answered, which is the state the bound exists
    to end, and the elapsed time is the measurement.

    ⛔ AND IT IS A STUB, NOT A MODE OF `dropssh relay`. A silence switch in the
    product would be a switch nobody sets and a path CI depends on. The whole
    thing is 60 lines of the wire format, and the wire format is already in
    this file.

    ⛔ THE BUG IT WAS BUILT FOR IS REAL AND WAS MEASURED. The first version of
    this case ran against `dropssh relay` with no node attached. That relay
    holds the operator on the upgrade and closes an unanswered session with
    1013 `node open timeout` after 15 s (measured 2026-09-28 at r11; this
    comment previously said 1008 at about ten seconds, which was wrong in both
    numbers), so the client exited well inside its own bound and the case was
    green for the wrong reason: it was asserting the RELAY's timeout, not the
    CLIENT's. Both paths are now asserted, and the one with the stub below is
    the one that reaches the bound.
    """

    def __init__(self, path):
        threading.Thread.__init__(self, daemon=True)
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(8)
        self.stop = False
        self.upgraded = threading.Event()
        self.sent_open = threading.Event()
        self.err = None

    def run(self):
        try:
            while not self.stop:
                try:
                    conn, _ = self.sock.accept()
                except OSError:
                    return
                try:
                    self._session(conn)
                except Exception as e:
                    self.err = e
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        except Exception as e:
            self.err = e

    def _session(self, conn):
        conn.settimeout(30)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return                      # refused before the upgrade
            buf += chunk
        head = buf.split(b"\r\n\r\n", 1)[0]
        m = re.search(rb"Sec-WebSocket-Key:\s*(\S+)", head, re.I)
        if not m:
            return
        key = m.group(1)
        want = base64.b64encode(hashlib.sha1(key + GUID).digest()).decode()
        conn.sendall((
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "X-Relay-Version: reverse-v1\r\n"
            "\r\n" % want).encode())
        self.upgraded.set()
        if b"/v1/connect/" in head:
            # ⛔ THE PROTOCOL, AND THEN THE SILENCE. `hello` is what every node
            # gets on its upgrade, `open` is what the operator waits on, and a
            # `ready` is what never comes. Nothing is ever closed, so the only
            # thing that can end this session is the client's own bound.
            conn.sendall(encode_frame(0x1, json_bytes(
                {"type": "hello", "version": 1,
                 "maxFrameBytes": 65536, "maxSessions": 64}), True))
            conn.sendall(encode_frame(0x1, json_bytes(
                {"type": "open", "id": ID_LEN * "a"}), True))
            self.sent_open.set()
        # Read and discard whatever the client sends, so its writes do not fill
        # the socket buffer and block it -- an operator blocked in write has not
        # reached the wait this stub exists to hold it in.
        try:
            while True:
                if not conn.recv(65536):
                    break
        except Exception:
            pass

    def shutdown(self):
        self.stop = True
        try:
            self.sock.close()
        except Exception:
            pass


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
def _probe_body(dropssh, work):
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
        after_text = 60000
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
            s = run_case(sock_path, "case2", node_sends_id_prefix=False,
                         expect_node_close=True)
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
            s = run_case(sock_path, "case3", node_sends_id_prefix=True,
                         node_text=True, expect_node_close=True)
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
        # closed with an open timeout (1013 `node open timeout`, measured at
        # r11; this comment previously said 1008) -- a refused login reported
        # to ssh as a success. That half is real and is asserted below.
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

        # ---- case 8: THE BOUND ON THE `ready` WAIT. THIS IS U1.
        #
        # ⛔ Case 6 cannot reach this, AND THAT IS THE WHOLE POINT OF THIS CASE.
        # Case 6 drives a name with no node at the real relay, and the real relay
        # holds the operator on the upgrade and closes it with 1008 after about
        # ten seconds. So case 6 measures the RELAY's timeout, and a client with
        # no bound at all would pass it. The bound under test is the one for a
        # relay that never closes, which is unreachable against a relay that
        # always closes, and the probe's own comment on case 6 already admits
        # the ready-gate was "0 times in 10 runs" as a plant for the same
        # reason.
        #
        # So: a stub relay that completes the upgrade, speaks the protocol, and
        # never sends `ready` and never closes. See SilentNodeRelay.
        ready_bound_failures = []
        #
        # ⛔ WHAT IS ASSERTED, AND WHY EACH HALF IS HERE.
        #
        #   the exit is non-zero -- an ssh reading a clean exit from its
        #   ProxyCommand reports a transport that worked, and a session that was
        #   never established is not one that completed.
        #
        #   the elapsed time is >= the bound -- WITHOUT THIS THE CASE IS
        #   DECORATION. Any early exit, including a crash and including the
        #   "Connection closed" that a stub which refused the upgrade would
        #   produce, passes the check above. The lower bound is the assertion
        #   that the client really spent the wait.
        #
        #   the elapsed time is under a slack above the bound -- so the wait is
        #   bounded rather than merely eventual. Without it, a bound that fires
        #   in 61 minutes passes.
        #
        #   the message names `ready` -- an operator told "connection closed"
        #   has to try the next idea in the wrong order. `1008 node open
        #   timeout` is the message on the OTHER path, and this one must not be
        #   that, because a stub that never closes must not produce it.
        # ⛔ THE BOUND IS READ FROM THE BINARY, NOT PASSED BY THIS FILE. Nothing
        # in the suite passes --bound-ms; the probe reads the default out of
        # `connect --help` so the number it measures against is a property of
        # the BUILD. A case that only fires under a flag it sets itself is
        # decoration, which is the disease this file is about. And 0 is not a
        # fast bound to be tolerated -- it is how "the bound was deleted"
        # compiles, so it is the state the case must catch.
        #
        # ⛔ AND THE FIRST VERSION OF THIS PARSE WAS WRONG IN A WAY THAT STILL
        # LOOKED LIKE IT WORKED. It read `--bound-ms[= ]+(\d+)`, which does not
        # match anything in the help text, because what follows the option name
        # there is its argument PLACEHOLDER `N` and not a number -- so the
        # search found nothing and the probe fell back to 60000. On the correct
        # build that fallback is the right number and the case passes, and on a
        # build with the bound at 0 it is the wrong number and the case fails
        # for the right REASON BY ACCIDENT, in the branch meant for a working
        # bound. A fallback that happens to equal the correct answer is the
        # hardest kind of wrong: it is invisible exactly when the thing it
        # stands in for is right.
        #
        # So the number is read from the sentence the help actually prints, and
        # a build whose help does not print one is a FAILURE rather than a
        # default. Silently guessing here would put the whole case's meaning
        # in the fallback.
        try:
            help_text = subprocess.run(
                [dropssh, "connect", "--help"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=20).stdout
        except Exception as e:
            help_text = b""
            ready_bound_failures.append(
                "could not read `connect --help` from the binary under test "
                "(%s), so the `ready` bound it reports is unknown and this case "
                "cannot assert anything: %s" % (dropssh, e))
        m = re.search(rb"bound-ms\b.*?Default is\s+(\d+)\s*ms", help_text, re.S)
        if m:
            after_text = int(m.group(1))
        else:
            after_text = -1
            ready_bound_failures.append(
                "`connect --help` does not print a default for --bound-ms, so "
                "the bound in this build cannot be measured against a number it "
                "itself reports. The case is skipped rather than guessed at, "
                "because a fallback that happens to equal the right answer is "
                "invisible exactly when the thing it stands in for is right.")

        # ⛔ ONE STUB, AND BOTH ASSERTIONS RUN AGAINST IT. The first version of
        # this case had two independent sub-cases, and the zero one ran BEFORE
        # the stub was created -- so on a build with no bound the positive
        # assertions still ran and reported a failure that was really the
        # positive assertions declining to apply. Two paths, one fixture, and
        # the branch is chosen by what the BINARY says it does.
        stub_path = os.path.join(
            work, "muxprobe-stub-%d-%d.sock" % (os.getpid(),
                                               int(time.time() * 1000) % 100000))
        stub = None
        ready_wait_s = after_text / 1000.0 if after_text > 0 else 0
        try:
            stub = SilentNodeRelay(stub_path)
            stub.start()
            t0 = time.time()
            r = subprocess.run(
                [dropssh, "connect", "--relay", "unix://" + stub_path,
                 "--name", "case8-silent-node"],
                input=b"SSH-2.0-GateProbe\r\n",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            elapsed = time.time() - t0
            if r.returncode == 0:
                ready_bound_failures.append(
                    "`dropssh connect` exited 0 after a silent node gave up on "
                    "the wait: a session that was never established is being "
                    "reported to ssh as one that completed")
            if b"ready" not in r.stderr:
                ready_bound_failures.append(
                    "the message for a silent node did not name `ready`, so an "
                    "operator cannot tell it from a refused upgrade: %r"
                    % r.stderr[:200])
            # ⛔ THE RELAY'S OWN CLOSE MUST NOT BE WHAT ENDED THIS, AND THE
            # CHECK IS ON THE SENTENCE THAT CLAIMS TO BE THE DIAGNOSIS RATHER
            # THAN ON THE WORD "1008" ANYWHERE.
            #
            # The first version of this was `b"1008" in r.stderr or
            # b"node open timeout" in r.stderr`, which is a substring test over
            # the whole log. It went red the moment the message was corrected,
            # because the corrected progress line MENTIONS 1008 while
            # explaining that it is not what happened here. The test was
            # asserting a word, not the behaviour, and it failed for a
            # reason that had nothing to do with the bound.
            #
            # ⛔ AND NOTE THAT THE RELAY'S REAL CLOSE FOR THIS IS NOT 1008. It
            # was measured against tcp.ssh.relay.ajam.dev on 2026-09-28: an
            # unanswered `open` is closed **1013 `node open timeout` at 15 s**.
            # So a substring test for the wrong code was passing for the wrong
            # reason twice over.
            #
            # What is asserted now is the one that cannot be faked: this stub
            # never closes the socket, so the ONLY thing that can end the
            # session is the client's own bound, and the message it prints on
            # that path names its own bound rather than a relay close. The
            # elapsed-time assertions below already prove the bound fired.
            if b"relay closed with 1013" in r.stderr or \
               b"relay closed with 1008" in r.stderr or \
               b"connection closed before the node answered" in r.stderr:
                ready_bound_failures.append(
                    "the silent-node session ended on a RELAY close rather than "
                    "on this client's own bound, so the bound under test was "
                    "never exercised: %r" % r.stderr[:200])
            if after_text == 0:
                # ⛔ A BOUND OF 0 IS A BUILD WITH NO BOUND, AND THE CASE FAILS IT.
                # This branch is not a second opinion on a working build; it is
                # the shape a "the bound was deleted" plant takes once the
                # option exists, and its job is to SAY SO.
                #
                # ⛔ AND IT CANNOT BE ASSERTED ON ELAPSED TIME ALONE. A bound of
                # 0 ends the wait on its first turn -- measured at 0.0s against
                # this stub -- which is faster than any real bound and is the
                # whole defect: `connect` gives up on a `ready` that has not
                # had time to arrive, reports a node that is not answering, and
                # ssh's ProxyCommand has exited for a reason that does not
                # exist. So the assertion is that the wait was NOT bounded
                # properly, and it is written as a failure rather than a skip
                # because "this build has no bound" is a broken build, not an
                # unsupported one.
                ready_bound_failures.append(
                    "this build's `ready` bound is 0, so `connect` ends the wait "
                    "with no bound at all: it gave up after %.1fs on a relay "
                    "that had sent `open` and was waiting, and an ssh "
                    "ProxyCommand that exits there reports a node that is not "
                    "answering when the node simply had not been asked yet. The "
                    "bound under test is missing." % elapsed)
            elif after_text > 0:
                if not stub.sent_open.is_set():
                    ready_bound_failures.append(
                        "the stub relay never sent `open`, so the client was not "
                        "waiting for a `ready` and this case measured something "
                        "else")
                # ⛔ THE LOWER BOUND IS ONE SECOND UNDER THE BOUND, AND A
                # SUBTRACTION CANNOT MAKE IT EXACT.
                #
                # The first version asserted `elapsed >= 60s`, which is a claim
                # about a measurement of a deadline: `dropssh connect` fires the
                # bound at 60 s and the harness measures the time AROUND it, so
                # the reading is 60.0s minus however long the two clocks
                # disagreed. It failed roughly one run in four with
                #
                #     gave up on the `ready` wait after 60.0s, so the 60s bound
                #     did not fire
                #
                # ⛔ WHICH IS A MESSAGE THAT CONTRADICTS ITS OWN NUMBER, and it
                # took three runs to decide it was a boundary and not a defect.
                # A test that fails at the boundary it is asserting is not
                # measuring the bound, it is measuring the scheduler.
                #
                # ⛔ AND THE ONE SECOND IS NOT ARBITRARY: it is an order of
                # magnitude above the disagreement between two clocks measuring
                # the same 60 seconds, and an order of magnitude below the
                # difference between "the bound fired" and "it returned early",
                # which is the thing the assertion is actually for. A build that
                # fires at 0.0s still fails this by fifty-nine seconds.
                if elapsed < ready_wait_s - 1.0:
                    ready_bound_failures.append(
                        "`dropssh connect` gave up on the `ready` wait after "
                        "%.2fs, which is more than a second before the %ds "
                        "bound, so the bound did not fire; an ssh ProxyCommand "
                        "that returns early here did not wait, it exited"
                        % (elapsed, ready_wait_s))
                if elapsed > ready_wait_s + 30:
                    ready_bound_failures.append(
                        "`dropssh connect` took %.1fs to end the `ready` wait, "
                        "more than 30s past the %ds bound: the wait is eventual, "
                        "not bounded" % (elapsed, ready_wait_s))
        except subprocess.TimeoutExpired:
            ready_bound_failures.append(
                "`dropssh connect` did not return within 180s against a relay "
                "that upgraded it and then said nothing; the wait for `ready` is "
                "not bounded, and this process is an ssh ProxyCommand, so ssh "
                "never times out")
        except Exception as e:
            ready_bound_failures.append("the silent-node case could not run: %s" % e)
        finally:
            if stub is not None:
                stub.shutdown()
            try:
                os.unlink(stub_path)
            except OSError:
                pass
        failures.extend(ready_bound_failures)

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

        # ---- case 9: a REFUSAL *BELOW* THE SESSION MOVE. THIS IS U2.
        #
        # `docs/relay-issues.md` U2 was 0/6 on the plant for a reason that was
        # itself the finding: the operator's WsSession is MOVED into the
        # Client rather than copied, and the case that would prove it was a
        # refusal that runs AFTER the move. Every refusal in the original suite
        # -- the peer cap, the session limit, no node -- sits ABOVE the move,
        # so reverting the move to a `memcpy` changed nothing any of them could
        # see. The probe reported 0/6 and the reason was correct.
        #
        # There is exactly ONE path below the move that closes the session: the
        # `if (!open_ok)` block, taken when the `open` cannot be written to the
        # node. So the case drives that, and asserts the cheap property that a
        # double free cannot pass: the relay is still serving afterwards.
        #
        # ⛔ AND THE TWO PLANTS THIS CASE HAS TO CATCH, WHICH ARE NOT THE SAME.
        #   the move reverted to a copy (`c->ws = ws`, no clear) -- the alias
        #   the move exists to prevent, and the one U2 names.
        #   the node's context freed with no reference -- the use-after-free
        #   that the same code path reaches, and one that was live on BOTH the
        #   data path and this one before the node was given a refcount.
        move_failures = []
        movesock = os.path.join(
            work, "muxmove-%d-%d.sock" % (os.getpid(),
                                           int(time.time() * 1000) % 100000))
        movelog = open(os.path.join(work, "muxprobe-move.log"), "wb")
        moverelay = subprocess.Popen(
            [dropssh, "relay", "--listen", "unix://" + movesock],
            stdout=subprocess.DEVNULL, stderr=movelog)
        try:
            for _ in range(200):
                if os.path.exists(movesock):
                    break
                time.sleep(0.05)
            # The node attaches, and then vanishes. The operator arrives while
            # the node is going away, so the `open` it tries to write is either
            # refused outright (`node_ws` already cleared) or written into a
            # node that is on its way out. Both are the `!open_ok` path, and
            # both run BELOW the move.
            mnode = connect_relay(movesock)
            mnb = handshake(mnode, "/v1/node/move9")
            mnr = Reader(mnode)
            mnr.buf = mnb
            deadline = time.time() + 5
            while time.time() < deadline:
                if not mnr.feed(0.2):
                    break
                f = mnr.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                    break
            mnode.close()
            # Give the node's own thread time to run its exit path, so the
            # operator below is attaching to a name whose node is going away.
            time.sleep(0.4)
            ops9 = 0
            for _ in range(4):
                try:
                    o = connect_relay(movesock)
                    handshake(o, "/v1/connect/move9")
                    ops9 += 1
                except RuntimeError as e:
                    # A refusal AT THE UPGRADE is the other shape of the same
                    # race and is also a path that closes a session.
                    if "503" not in str(e) and "409" not in str(e):
                        raise
            time.sleep(1.0)
            probe9 = connect_relay(movesock)
            b9 = handshake(probe9, "/v1/node/move9-after")
            p9 = Reader(probe9)
            p9.buf = b9
            alive9 = False
            deadline = time.time() + 5
            while time.time() < deadline:
                if not p9.feed(0.2):
                    break
                f = p9.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                    alive9 = True
                    break
            probe9.close()
            if not alive9:
                move_failures.append(
                    "after a refusal below the session move the relay did not "
                    "serve a NEW node: the process is gone, which is what an "
                    "aliased session owner or a freed node context does")
        except Exception as e:
            move_failures.append("the below-the-move case could not run: %s" % e)
        finally:
            moverelay.terminate()
            try:
                moverelay.wait(timeout=5)
            except Exception:
                moverelay.kill()
            movelog.close()
            try:
                os.unlink(movesock)
            except OSError:
                pass
        failures.extend(move_failures)

        # ---- case 10: THE 1011 SWEEP, AND WHETHER IT HOLDS A REFERENCE. U3.
        #
        # Case 4 forces the ordering -- a node disconnects with an operator
        # attached -- and that is the right ordering, but the window between
        # the sweep taking a `Client *` and the operator's own thread freeing
        # it is narrower than a probe run, which is why U3 was 0/6.
        #
        # ⛔ SO THE RACE IS NOT MADE BIGGER BY LOOPING; IT IS STOOD AT ON
        # PURPOSE. `DROPSSH_RELAY_FAULT` names an injection point in the relay
        # and the relay yields there, so the two threads are given every chance
        # to interleave at exactly the two ends of the window. The correctness
        # of the fixed build does not depend on the scheduling at all: with the
        # reference held, the operator's unref only decrements a count.
        #
        # ⛔ AND THE PLANT IS WHAT PROVES THE CASE. Removing `c->refs++` from
        # the sweep is caught as a relay that no longer serves. That plant is
        # the plant U3 reported as 0/6, and the count is in `docs/relay-issues.md`.
        sweep_failures = []
        sweepsock = os.path.join(
            work, "muxsweep-%d-%d.sock" % (os.getpid(),
                                           int(time.time() * 1000) % 100000))
        sweeplog = open(os.path.join(work, "muxprobe-sweep.log"), "wb")
        env = dict(os.environ)
        env["DROPSSH_RELAY_FAULT"] = "sweep-release"
        sweeprelay = subprocess.Popen(
            [dropssh, "relay", "--listen", "unix://" + sweepsock],
            stdout=subprocess.DEVNULL, stderr=sweeplog, env=env)
        try:
            for _ in range(200):
                if os.path.exists(sweepsock):
                    break
                time.sleep(0.05)
            snode = connect_relay(sweepsock)
            snb = handshake(snode, "/v1/node/sweep10")
            snr = Reader(snode)
            snr.buf = snb
            deadline = time.time() + 5
            while time.time() < deadline:
                if not snr.feed(0.2):
                    break
                f = snr.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                    break
            sop = connect_relay(sweepsock)
            sob = handshake(sop, "/v1/connect/sweep10")
            sor = Reader(sop)
            sor.buf = sob
            # The operator must be attached, and the node must not have
            # answered `ready` yet: an attached operator with an unready
            # session is the state the 1011 sweep exists to end.
            deadline = time.time() + 8
            attached = False
            while time.time() < deadline and not attached:
                if not snr.feed(0.2):
                    break
                f = snr.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "open":
                    attached = True
            if not attached:
                sweep_failures.append(
                    "the sweep case never attached an operator, so the 1011 "
                    "sweep had nothing to sweep and the case measured nothing")
            # The node goes, and the operator's own socket goes with it, so the
            # operator's thread is racing its last unref against the sweep.
            snode.close()
            time.sleep(0.2)
            sop.close()
            time.sleep(2.0)
            probe10 = connect_relay(sweepsock)
            b10 = handshake(probe10, "/v1/node/sweep10-after")
            p10 = Reader(probe10)
            p10.buf = b10
            alive10 = False
            deadline = time.time() + 5
            while time.time() < deadline:
                if not p10.feed(0.2):
                    break
                f = p10.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                    alive10 = True
                    break
            probe10.close()
            if not alive10:
                sweep_failures.append(
                    "the 1011 sweep with the fault injected at its own release "
                    "point took the relay down: the process is gone, which is "
                    "what a sweep that holds no reference does")
        except Exception as e:
            sweep_failures.append("the 1011-sweep case could not run: %s" % e)
        finally:
            sweeprelay.terminate()
            try:
                sweeprelay.wait(timeout=5)
            except Exception:
                sweeprelay.kill()
            sweeplog.close()
            try:
                os.unlink(sweepsock)
            except OSError:
                pass
        failures.extend(sweep_failures)

        # ---- case 14: AN OPERATOR WRITING WHILE THE NODE DISCONNECTS.
        #
        # ⛔ ⛔ AND THE FIRST THING TO SAY IS THAT THIS CASE DOES NOT CATCH THE
        # DEFECT IT WAS WRITTEN FOR. Four constructions were tried, the last of
        # them with a fault point that parks the writer until the node's exit
        # has happened, and a relay with the refcount REMOVED still served
        # every time -- 379 writes across the disconnect, then 38 with the
        # writer held, no crash. ⛔ THE REASON, MEASURED AND NOT GUESSED:
        # `node_done` ends with `ws_close(ws)`, so the node's session buffers
        # are freed BEFORE the connection thread reaches `free(nc)`. By the
        # time the NodeCtx goes, the session an operator is holding is already
        # closed, `ws_write` returns -1 on it, and the operator's thread leaves.
        # The refcount is therefore DEFENCE IN DEPTH and not the load-bearing
        # guard; what makes the write safe today is the ordering plus the
        # `t == NULL` check in the write paths.
        #
        # ⛔ SO WHAT IS THIS CASE FOR, AND WHY IT IS HERE ANYWAY. It holds the
        # two threads on top of each other, which is the only way to OBSERVE
        # that the ordering is what protects them. Remove either the ordering
        # or the `t == NULL` check and this case is where it will show. Keeping
        # it costs one relay and one case run; deleting it because it does not
        # currently go red would be deleting the instrument that would go red
        # if the protection were ever moved.
        #
        # ⛔ AND THE ORIGINAL DEFECT IS STILL REAL AND STILL DOCUMENTED.
        # `NameSlot.node` was a `WsSession *` pointing INTO a heap NodeCtx, and
        # `wlock` never protected it: the node's exit path never took that
        # lock, so it only ever serialised OPERATORS against each other. What
        # the measurement above adds is the ORDER in which two independent
        # things protect it, and that is worth more than the claim that a
        # refcount is load bearing when it is not.
        #
        # ⛔ AND CASE 4 DOES NOT CATCH IT, WHICH IS WHY IT WAS MISSED. Case 4's
        # operator is attached and IDLE -- it is parked in a read, holding no
        # reference and about to write nothing -- so the node can be freed with
        # nothing pointing at it. The window is a WRITE, so the operator has to
        # be WRITING when the node leaves, and a case that closes the operator
        # after the node cannot see a defect whose whole shape is the reverse.
        #
        # The construction: an operator attached and open, a node that is about
        # to vanish, and the operator writing CONTINUOUSLY so that a write is
        # in flight across the node's exit. The assertion is the cheap one a
        # use-after-free cannot pass: the relay is still serving afterwards.
        uaf_failures = []
        uaf_sock = os.path.join(
            work, "muxuaf-%d-%d.sock" % (os.getpid(),
                                          int(time.time() * 1000) % 100000))
        uaf_log = open(os.path.join(work, "muxprobe-uaf.log"), "wb")
        uaf_env = dict(os.environ)
        # ⛔ `write-in-flight`, NOT `node-exit-free`, and the difference is the
        # whole case. Holding the node's exit only yields a thread that is not
        # there: measured, a probe driving 380 writes across a disconnect found
        # the relay serving on a correct build AND on one with the refcount
        # removed, because the operator's writes complete into a socket the
        # relay drains and it is almost never inside `ws_write` at that
        # instant. ⛔ HOLDING THE WRITE PUTS THE TWO THREADS ON TOP OF EACH OTHER
        # BY CONSTRUCTION INSTEAD OF BY LUCK.
        uaf_env["DROPSSH_RELAY_FAULT"] = "write-in-flight"
        uaf_relay = subprocess.Popen(
            [dropssh, "relay", "--listen", "unix://" + uaf_sock],
            stdout=subprocess.DEVNULL, stderr=uaf_log, env=uaf_env)
        try:
            for _ in range(200):
                if os.path.exists(uaf_sock):
                    break
                time.sleep(0.05)
            # ⛔ A LOCAL, NOT `sock_path`. The first version rebound the shared
            # name to the fault relay's socket, so every case AFTER this one
            # looked for a socket that had been unlinked -- and the failures
            # were "the stdin-EOF case could not run: No such file or
            # directory", naming a case that had nothing to do with what
            # changed. ⛔ A case must not move the ground the next one stands on.
            uaf_path = uaf_sock
            # The operator keeps writing for as long as the relay lives. Each
            # write goes through the node's socket under wlock, which is the
            # window the refcount covers.
            import threading
            uaf_state = {"stop": False, "wrote": 0, "err": None}

            def _writer(sock, sid):
                payload = b"UAF-PROBE-" * 64
                frame = encode_frame(0x2, sid.encode() + payload, True)
                while not uaf_state["stop"]:
                    try:
                        sock.sendall(frame)
                        uaf_state["wrote"] += 1
                    except Exception as e:
                        uaf_state["err"] = e
                        return
                    time.sleep(0.001)

            unode = connect_relay(uaf_path)
            unb = handshake(unode, "/v1/node/uaf14")
            unr = Reader(unode)
            unr.buf = unb
            deadline = time.time() + 5
            while time.time() < deadline:
                if not unr.feed(0.2):
                    break
                f = unr.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                    break
            # ⛔ THE OPERATOR'S UPGRADE IS RETRIED, AND THE RETRY IS THE WAIT.
            #
            # Two waits were tried and both were wrong in the same way. Waiting
            # for the node's `hello` frame does not work, because `node_thread`
            # writes `hello` as its FIRST statement, before the connection
            # thread has published `ns->node` under `tlock` -- so a probe can
            # see `hello` and still be refused with 503, and it was: the log
            # said "node uaf14 connected" and the operator still got "the node
            # is not connected". Waiting for the relay's own log line does not
            # work either, because its stderr is block-buffered when it is a
            # pipe and the probe cannot see a line that has not been flushed.
            #
            # Retrying the UPGRADE is the only wait that observes the thing
            # being waited for: the relay answers 503 when the node is absent
            # and 101 when it is there, so a refusal is a definite answer and a
            # retry is the correct response to it. Both earlier waits inferred
            # internal state from the outside and then reported their own race
            # as a product fault -- "the write-across-disconnect case could not
            # run: 503" is a case that failed to set itself up.
            uop = None
            for _ in range(40):
                try:
                    cand = connect_relay(uaf_path)
                    cand.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF,
                                     4 << 20)
                    cand.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                     4 << 20)
                    uob = handshake(cand, "/v1/connect/uaf14")
                    uop = cand
                    break
                except RuntimeError as e:
                    if "503" not in str(e):
                        raise
                    time.sleep(0.1)
            if uop is None:
                raise RuntimeError("the node never became connectable on the "
                                   "fault relay: 503 after 40 attempts")
            uor = Reader(uop)
            uor.buf = uob
            usid = None
            deadline = time.time() + 8
            while time.time() < deadline and usid is None:
                if not unr.feed(0.2):
                    break
                f = unr.take()
                if f and f[0] == 0x1 and parse_json(f[1]).get("type") == "open":
                    usid = parse_json(f[1]).get("id")
            if not usid:
                uaf_failures.append(
                    "the operator never reached the node, so case 14 measured "
                    "nothing about a write across a node's exit")
            else:
                unode.sendall(encode_frame(
                    0x1, json_bytes({"type": "ready", "id": usid}), True))
                # the operator must see `ready` before it may write at all: the
                # relay refuses early data, and an early write would be closed
                # 1008 rather than reaching the write path this case is about
                deadline = time.time() + 5
                while time.time() < deadline:
                    if not uor.feed(0.2):
                        break
                    f = uor.take()
                    if f and f[0] == 0x1 and \
                            parse_json(f[1]).get("type") == "ready":
                        break
                # ⛔ AND THE WRITER KEEPS ITS SOCKET. The first version closed
                # the operator immediately after closing the node, which broke
                # the writer at once -- measured, 379 writes and a
                # BrokenPipeError -- so there was never a write in flight when
                # the node was freed, and the case was green on a relay that
                # frees the node's context with no reference at all. ⛔ THE
                # ORDERING IS THE WHOLE CASE: the node leaves, and the operator
                # carries on writing into a socket whose far end is gone, which
                # is exactly the shape of a session that outlives its node.
                th = threading.Thread(target=_writer, args=(uop, usid),
                                      daemon=True)
                th.start()
                deadline = time.time() + 5
                while time.time() < deadline and uaf_state["wrote"] < 5:
                    time.sleep(0.02)
                unode.close()
                time.sleep(0.5)
                uaf_state["stop"] = True
                try:
                    uop.close()
                except Exception:
                    pass
                time.sleep(1.5)
                probe14 = connect_relay(uaf_path)
                b14 = handshake(probe14, "/v1/node/uaf14-after")
                p14 = Reader(probe14)
                p14.buf = b14
                alive14 = False
                deadline = time.time() + 5
                while time.time() < deadline:
                    if not p14.feed(0.2):
                        break
                    f = p14.take()
                    if f and f[0] == 0x1 and \
                            parse_json(f[1]).get("type") == "hello":
                        alive14 = True
                        break
                probe14.close()
                if not alive14:
                    uaf_failures.append(
                        "a node that disconnected while an operator was WRITING "
                        "took the relay down (the operator completed %d writes, "
                        "err %r). The node's context is freed on its way out "
                        "and an operator holding a pointer into it is writing "
                        "through freed memory; `wlock` does not prevent it "
                        "because the exit path never took that lock"
                        % (uaf_state["wrote"], uaf_state["err"]))
        except Exception as e:
            # ⛔ AND A CRASH OF THE FAULT RELAY IS THE DEFECT, NAMED AS SUCH.
            # The first version of this branch reported every exception as "the
            # case could not run", and on a relay with the use-after-free
            # restored that is a crash -- the relay process is gone, so its
            # socket cannot be connected and every later step raises ENOENT.
            # A case that reports a crash as a case that could not set itself up
            # has hidden the very thing it exists to find, and it did so three
            # runs in a row with a perfect 3/3.
            msg = str(e)
            if "No such file or directory" in msg or \
               "Connection refused" in msg:
                uaf_failures.append(
                    "the fault relay is GONE (%s). A node disconnecting while an "
                    "operator is writing freed the node's context under a write "
                    "in flight, and the whole relay -- every other node and "
                    "operator on it -- went with it. The operator completed %d "
                    "writes before the crash." % (msg, uaf_state.get("wrote", 0))
                    if "uaf_state" in dir() else
                    "the fault relay is GONE (%s), which is the use-after-free "
                    "this case exists to catch" % msg)
            else:
                uaf_failures.append(
                    "the write-across-disconnect case could not run: %s" % e)
        finally:
            try:
                uaf_relay.terminate()
                uaf_relay.wait(timeout=5)
            except Exception:
                uaf_relay.kill()
            uaf_log.close()
            try:
                os.unlink(uaf_sock)
            except OSError:
                pass
        failures.extend(uaf_failures)


        # ---- case 11: A LARGE TRANSFER REACHES THE FAR SIDE WITH THE SOCKET
        # OPEN, AND THIS IS A CASE ABOUT A REAL DATA-LOSS DEFECT.
        #
        # wstunnel#360 is the reference: the maintainer shipped a flush bug
        # where data was accepted into a buffer and never delivered until a
        # boundary, and the only symptom was a transfer that appeared to hang.
        #
        # ⛔ THIS CASE FOUND ONE IN OUR OWN RELAY, AND IT IS NOT A FLUSH BUG.
        # `relay.c` clamped an operator's frame to the node's advertised
        # `maxFrameBytes` before forwarding it:
        #
        #     if (mf && n + RELAY_ID_LEN > mf) {
        #         n = mf > RELAY_ID_LEN ? mf - RELAY_ID_LEN : 0;
        #     }
        #
        # so a 300000-byte frame arrived as 65536 bytes and the remaining
        # 234464 were never sent, with no close on either socket and nothing in
        # the log. The premise was wrong too: `maxFrameBytes` bounds one frame
        # on the wire and `ws_write` already honours it by CHUNKING, so the
        # clamp was enforcing a limit by the one method that could not do it
        # without losing data. Measured on the pre-fix binary, 1/1.
        flush_failures = []
        try:
            import threading
            s = run_case(sock_path, "case11", node_sends_id_prefix=True)
            big = b"Z" * 300000
            data = encode_frame(0x2, big, True)
            # ⛔ THE NODE READER IS EMPTIED OF THE HAPPY PATH'S OWN TRAFFIC
            # FIRST. `run_case` leaves an echo in it, and appending to that
            # reports a byte count that is the sum of two different transfers --
            # a failure that names the relay and is entirely the case's
            # arithmetic. The first version did exactly that and reported
            # 300039 bytes for a 300000-byte frame.
            while True:
                f = s.rn.take()
                if f is None:
                    break
                if f[0] == 0x2:
                    s.node_bin.append(f[1])
            del s.node_bin[:]

            # ⛔ THE WRITE IS PUMPED IN SLICES FROM A NON-BLOCKING SOCKET, NOT
            # DONE IN ONE sendall. A 300 KB `sendall` blocks until the far side
            # reads, and the reader is THIS thread, so the first version
            # deadlocked in its own write and timed out -- which would have been
            # recorded as a relay failure rather than as a broken case.
            sent = [0]
            stop = [False]

            def _writer():
                s.op.setblocking(False)
                while not stop[0] and sent[0] < len(data):
                    try:
                        n = s.op.send(data[sent[0]:sent[0] + 65536])
                        sent[0] += n
                    except BlockingIOError:
                        time.sleep(0.005)
                    except OSError:
                        break

            th = threading.Thread(target=_writer, daemon=True)
            th.start()
            got = b""
            deadline = time.time() + 30
            # ⛔ THE WINDOW IS THE POINT, AND THE SOCKET IS NEVER CLOSED. If the
            # relay delivers only at a boundary -- or drops the overflow, as
            # the version this case was written for did -- the bytes do not
            # arrive inside this window, and a case that closed the operator
            # first would be asserting the opposite of what it claims.
            while time.time() < deadline and len(got) < len(big) + 32:
                s.rn.feed(0.05)
                while True:
                    f = s.rn.take()
                    if f is None:
                        break
                    if f[0] == 0x2:
                        s.node_bin.append(f[1])
                    elif f[0] == 0x8:
                        code, reason = close_of(f[1])
                        s.node_close = (code, reason)
                got = b"".join(s.node_bin)
            stop[0] = True
            # ⛔ THE NODE LEG IS ID-PREFIXED, SO 300032 IS CORRECT AND 300000 IS
            # NOT. The relay prepends the 32-hex session id on the node's wire
            # and strips it for the operator; that is the whole asymmetry this
            # probe exists to pin (case 1). The first version of this
            # assertion compared the raw node bytes to the payload and so
            # reported a correct relay as losing 32 bytes.
            #
            # So the check is: the id is present, and everything after it is
            # the payload byte for byte. A clamping relay leaves the payload
            # short; a relay that mis-strips leaves it shifted.
            body = got[32:] if got[:32].isalnum() else b""
            if len(got) != len(big) + 32 or body != big:
                flush_failures.append(
                    "a %d-byte frame reached the node as %d bytes with the "
                    "socket still open (%d of the request was written, close "
                    "seen: %r). A relay that clamps a frame to the node's "
                    "maxFrameBytes loses the remainder with no close and no "
                    "log, and the only symptom is a transfer that stops part "
                    "way. See wstunnel#360 and docs/relay-issues.md."
                    % (len(big), len(got), sent[0], s.node_close))
            s.node.close()
            s.op.close()
        except Exception as e:
            flush_failures.append("the large-transfer case could not run: %s" % e)
        failures.extend(flush_failures)

        # ---- case 12: AN OPERATOR SURVIVES ITS OWN STDIN CLOSING.
        #
        # ⛔ THIS IS websocat#235, AND IT IS A BUG WE SHIPPED AND THEN SHIPPED
        # AGAIN. websocat's maintainer states the whole design in two sentences:
        # by default it waits for the other direction to also return 0 bytes
        # before considering the connection finished; with `-E` it drops
        # pending data and closes the other direction immediately.
        #
        # Our first implementation was `-E` and `-E`-plus-destroy: a websocket
        # Close on stdin EOF, which told the relay to tear every attached
        # operator down, so the node's reply arrived into a dead socket and the
        # operator exited having read nothing -- a close 1005 and silence. The
        # second stopped reading stdin and did nothing else, which is websocat's
        # default and is correct.
        #
        # ⛔ AND WE REINTRODUCED IT IN `d986214`: while adding a bound to the
        # `ready` wait, the reverse branch's `continue` was removed, and in the
        # first attempt that made the reverse path fall through into the
        # forward branch's blocking `ws_read`. The EOF and half-close discipline
        # is a property of the EVENT LOOP'S STRUCTURE and not of one call site,
        # and nothing in the code said so -- which is why the fix is a case
        # here rather than a comment in `connect.c`.
        #
        # The case drives it through the real binary: a node, a real
        # `dropssh connect` process, and that process's stdin closed while the
        # node still has bytes to send.
        eof_failures = []
        try:
            import threading
            # ⛔ THE NAME IS BUILT ONCE AND USED TWICE. The first version had
            # the node register as `eof12` and the operator ask for
            # `eof12-<pid>`, so the relay answered 503 on the operator's upgrade
            # -- a correct refusal of a request for a node that is not
            # connected under that name -- and the case reported "the operator
            # never reached the node". ⛔ THE SYMPTOM NAMED A PROPERTY OF
            # `dropssh connect` AND WAS ENTIRELY THE CASE'S OWN BOOKKEEPING.
            eof_name = "eof12-%d" % (os.getpid())
            enode = connect_relay(sock_path)
            enb = handshake(enode, "/v1/node/" + eof_name)
            enr = Reader(enode)
            enr.buf = enb

            # ⛔ THE NODE'S SOCKET IS DRAINED IN ITS OWN THREAD. Reading it only
            # between actions let the operator's echoed bytes and the node's own
            # frames coalesce on the wire while nothing was draining, and the
            # relay reported "the node sent framing this relay cannot read" --
            # a fault in the probe's unread socket that the case then read as a
            # fault in `dropssh connect`.
            node_frames = []
            node_stop = [False]

            def _nodedrain():
                while not node_stop[0]:
                    if not enr.feed(0.05):
                        break
                    while True:
                        f = enr.take()
                        if f is None:
                            break
                        node_frames.append(f)
                node_stop[0] = True

            threading.Thread(target=_nodedrain, daemon=True).start()

            def pop_node():
                return node_frames.pop(0) if node_frames else None

            deadline = time.time() + 5
            while time.time() < deadline:
                f = pop_node()
                if f is None:
                    time.sleep(0.02)
                    continue
                if f[0] == 0x1 and parse_json(f[1]).get("type") == "hello":
                    break

            p = subprocess.Popen(
                [dropssh, "connect", "--relay", "unix://" + sock_path,
                 "--name", eof_name],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL)
            collected = [b""]

            def _drain_out():
                try:
                    while True:
                        c = p.stdout.read(4096)
                        if not c:
                            break
                        collected[0] += c
                except Exception:
                    pass

            threading.Thread(target=_drain_out, daemon=True).start()
            try:
                p.stdin.write(b"SSH-2.0-EofProbe\r\n")
                p.stdin.flush()
                sid12 = None
                deadline = time.time() + 10
                while time.time() < deadline and sid12 is None:
                    f = pop_node()
                    if f is None:
                        time.sleep(0.02)
                        continue
                    if f[0] == 0x1 and parse_json(f[1]).get("type") == "open":
                        sid12 = parse_json(f[1]).get("id")
                if not sid12:
                    eof_failures.append(
                        "the operator never reached the node, so case 12 "
                        "measured nothing about stdin closing")
                else:
                    enode.sendall(encode_frame(
                        0x1, json_bytes({"type": "ready", "id": sid12}), True))
                    # ⛔ THE OPERATOR IS GIVEN TIME TO REACH ITS POLL LOOP
                    # BEFORE STDIN IS CLOSED. The gate opening and the EOF
                    # landing in the same instant is a legitimate race in a real
                    # session; here it would make the case a timing test rather
                    # than a test of the EOF invariant.
                    time.sleep(2.0)
                    # ⛔ STDIN IS CLOSED HERE, AND THE OPERATOR'S SOCKET IS LEFT
                    # OPEN AND THE NODE LEFT ALIVE. The invariant under test is
                    # websocat#235: stdin EOF is "no more input", not "the
                    # session is over". An implementation that treats it as a
                    # close tears the relay link down and EXITS, and the only
                    # thing wrong with the rest of the world is that it stopped
                    # reading. So the observation is the process's own state:
                    # still running, still reading, and able to deliver a node's
                    # bytes afterwards.
                    p.stdin.close()
                    time.sleep(3.0)
                    if p.poll() is not None:
                        eof_failures.append(
                            "`dropssh connect` EXITED %r within 3s of its stdin "
                            "closing, while the relay link was still open and a "
                            "node was still attached. An ssh ProxyCommand that "
                            "treats stdin EOF as the end of the session exits "
                            "having read nothing: this process's only channel is "
                            "stdout, and the node's reply is still coming "
                            "(websocat#235)" % (p.poll(),))
                    else:
                        # ⛔ AND IT STILL DELIVERS. A node frame at exactly the
                        # relay's advertised limit, id-prefixed as the node leg
                        # requires, must reach stdout with the operator's stdin
                        # closed. `mux-probe` case 11 and the e2e's 270 KB
                        # transfer establish the framing rules; this asserts
                        # that they still hold on the far side of an EOF.
                        # ⛔ AND THE NODE SENDS ONE MORE `ready` AFTERWARDS, AS
                        # A TEXT CONTROL FRAME, AND THE ASSERTION IS THAT THE
                        # OPERATOR IS STILL CONSUMING THE LINK.
                        #
                        # A data frame is not used here on purpose. A node data
                        # frame must carry the 32-hex id, and a probe that gets
                        # that wrong is closed 1009 -- so a data-frame probe
                        # measures the probe's framing before it measures the
                        # operator, and the first version of this case spent a
                        # long time failing on exactly that. A `ready` is text,
                        # cannot be mis-framed, and is consumed by the operator
                        # setting `seen_ready` again and staying in its loop.
                        #
                        # ⛔ WHAT IS AND IS NOT ESTABLISHED, STATED PLAINLY. This
                        # asserts that the operator is ALIVE and STILL READING
                        # the relay after its stdin closes, which is the
                        # invariant websocat#235 is about and the one this
                        # project shipped as a bug twice. It does NOT assert
                        # that session BYTES reach stdout after an EOF, because
                        # the way to observe that from outside is a real ssh on
                        # the far end, and that is what the e2e's 270 KB
                        # transfer through a real `dropssh connect` is for. A
                        # probe that cannot see stdout is not entitled to claim
                        # it measured the byte path, and a case that asserts it
                        # anyway is a case that will be red for a reason nobody
                        # can act on.
                        enode.sendall(encode_frame(
                            0x1, json_bytes({"type": "ready", "id": sid12,
                                             "phase": "after-stdin-eof"}), True))
                        time.sleep(3.0)
                        if p.poll() is not None:
                            eof_failures.append(
                                "the operator EXITED %r within 3s of a second "
                                "`ready` arriving on a link whose stdin had been "
                                "closed, so it had stopped reading the relay"
                                % (p.poll(),))
            finally:
                node_stop[0] = True
                try:
                    p.stdin.close()
                except Exception:
                    pass
                try:
                    p.wait(timeout=10)
                except Exception:
                    p.kill()
                    p.wait(timeout=5)
            enode.close()
        except Exception as e:
            eof_failures.append("the stdin-EOF case could not run: %s" % e)
        failures.extend(eof_failures)

        # ---- case 13: A FRAME AT EXACTLY maxFrameBytes IS HONOURED (websocat
        # #201's unmeasured memory assumption, dropssh#11 adopt shape 2).
        #
        # ⛔ `WS_MAX_FRAME` is 16 MiB and `decode_available` assembles a whole
        # message before delivering it, so the cost of one maximum-size message
        # is real and was never measured. The relay advertises 65536, so in
        # practice the assembly is bounded at 64 KiB by the peer -- and a peer
        # that ignored that would make this process allocate per frame.
        #
        # The case asserts the boundary from both sides: a frame at exactly
        # maxFrameBytes is delivered whole, and the relay's own advertised
        # number is what the client is chunking at, so the two agree.
        mem_failures = []
        try:
            s = run_case(sock_path, "case13", node_sends_id_prefix=True)
            del s.node_bin[:]
            # ⛔ THE PAYLOAD LIMIT ON THE NODE'S LEG IS maxFrameBytes MINUS THE
            # 32-HEX ID, and that is not a rounding detail: the relay PREPENDS
            # the id, so the frame on the wire is 32 bytes longer than the
            # payload. docs/reverse-relay.md records the rule as "node wire
            # <= 65568". The first version asked for a 65536-byte payload and
            # was told 65504 arrived, and reported it as a relay that lost
            # bytes -- when the relay was right and the case was arithmetic.
            limit = 65536 - 32
            payload = b"M" * limit
            s.op.sendall(encode_frame(0x2, payload, True))
            got = b""
            deadline = time.time() + 15
            while time.time() < deadline and len(got) < limit:
                s.rn.feed(0.05)
                while True:
                    f = s.rn.take()
                    if f is None:
                        break
                    if f[0] == 0x2:
                        s.node_bin.append(f[1])
                got = b"".join(s.node_bin)
            body13 = got[32:] if len(got) > 32 and got[:32].isalnum() else b""
            if len(body13) != limit:
                mem_failures.append(
                    "a frame of exactly the node leg's limit (%d bytes of "
                    "payload, 65536 less the 32-hex id) reached the node as "
                    "%d bytes. The limit is the memory cost of one message on "
                    "the wire, and a client that chunks at it must get the "
                    "whole chunk back" % (limit, len(body13)))
            s.node.close()
            s.op.close()
        except Exception as e:
            mem_failures.append("the maxFrameBytes case could not run: %s" % e)
        failures.extend(mem_failures)

        for f in failures:
            print("mux-probe: FAIL %s" % f)
        if not failures:
            print("mux-probe: id-prefix, bare-frame close 1009, text-frame "
                  "close 1003, the ready ordering, a bounded `connect` that "
                  "exits non-zero on a silent node, the 60s bound on the "
                  "`ready` wait itself, a node disconnect with an operator "
                  "attached, a refusal on the operator's own thread, a refusal "
                  "below the session move, the 1011 sweep with its race "
                  "injected at both ends, a 300 KB transfer that completes "
                  "with the socket open, an operator that survives its stdin "
                  "closing, and a frame at exactly maxFrameBytes all behave "
                  "as measured")
        return 1 if failures else 0
    finally:
        relay.terminate()
        try:
            relay.wait(timeout=5)
        except subprocess.TimeoutExpired:
            relay.kill()


def main():
    """Run the probe, and turn a relay that DIED into one named failure.

    ⛔ A RELAY THAT CRASHES MUST BE REPORTED AS A CRASH, NOT AS A TRACEBACK FROM
    AN UNRELATED CASE. Every double free in `src/relay.c` has taken the whole
    process down, and until now the probe showed that as a Python
    `ConnectionRefusedError` at whichever case happened to run next -- naming
    the wrong thing, which is the failure mode this file has been bitten by
    three times. So the body is wrapped: a dead relay, and a connection refused
    because of one, is reported as the crash it is, with the relay's own log
    tail, and the probe exits non-zero.
    """
    if len(sys.argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    dropssh, work = sys.argv[1], sys.argv[2]
    try:
        return _probe_body(dropssh, work)
    except (ConnectionRefusedError, ConnectionResetError) as e:
        return relay_died(work, e)
    except RuntimeError as e:
        # ⛔ A CASE THAT RAISED BECAUSE THE RELAY STOPPED ANSWERING IS THE SAME
        # FAILURE, AND IT ARRIVES AS A RuntimeError RATHER THAN AS A REFUSED
        # SOCKET. A relay killed by a double free stops completing handshakes,
        # so the next case to run is the one that times out waiting for a
        # `ready` and raises. Reporting that as "the node's ready did not
        # arrive" would blame the framing rules for a crash three cases earlier,
        # which is the exact "a failure that names the wrong thing" this file
        # exists to stop.
        if "did not reach the operator" in str(e) or "sent no open" in str(e) \
           or "sent no hello" in str(e):
            return relay_died(work, e)
        raise


def relay_died(work, e):
    """Report a relay that is no longer answering as the crash it is.

    The relay's own logs are printed with each, because each of the four relay
    processes the probe starts writes a different one and a reader otherwise
    has no way to tell which of them died.
    """
    print("mux-probe: FAIL the relay process is GONE (%s). A relay that dies "
          "takes down every node and operator on it, and that is what a double "
          "free, a use-after-free or an unguarded 1011 sweep does. This is the "
          "crash itself, reported here rather than as a traceback from "
          "whichever case happened to run next." % e)
    for name in ("muxprobe-relay.log", "muxprobe-limit.log",
                 "muxprobe-move.log", "muxprobe-sweep.log"):
        path = os.path.join(work, name)
        if not os.path.exists(path):
            continue
        with open(path, "rb") as fh:
            tail = fh.read()[-800:].decode("utf-8", "replace").rstrip()
        print("mux-probe: %s ended with:\n%s" % (name, tail))
    return 1


if __name__ == "__main__":
    sys.exit(main())
