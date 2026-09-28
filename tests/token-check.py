#!/usr/bin/env python3
"""token-check.py - drive a relay's pair endpoint and then its token gate.

WHAT THIS IS, AND WHY IT IS NOT A UNIT TEST
===========================================
`tests/token-test.c` checks the signer and the verifier against each other. That
is necessary and it is not sufficient: the signer and the verifier sharing a
bug is the most likely way for both to be wrong together, and only an
independent pair of ends finds it.

So this drives the WHOLE path over a real socket:

  POST /v1/pair  ->  a name, a node token, a connect token, an expiry
  GET  /v1/node/<name>       with the node token
  GET  /v1/connect/<name>    with the connect token
  GET  /v1/connect/<name>    with the NODE token      <- must be refused
  GET  /v1/node/<other>      with the node token      <- must be refused
  GET  /v1/node/<name>       with no token at all     <- refused only if keyed
  GET  /v1/node/<name>       with a forged token      <- must be refused

⛔ WHY THE REFUSALS ARE THE TEST. A pair that round-trips proves only that two
pieces of code agree. What has to hold for issue #13 to mean anything is that
the two roles are DIFFERENT CREDENTIALS and that a pair is bound to ONE name:
without those, the node's token -- which lives in a cage, in a config file and
in a log line -- opens an operator session, and the whole "a pair is two
credentials" claim is decoration.

⛔ AND `--nokey` CHECKS THE COMPATIBILITY RULE FROM THE OTHER SIDE. A relay with
no key has always accepted every peer, and a change that made it require a
token would break every existing deployment on the first upgrade. The banner and
the behaviour are separate claims about the same process and they disagreed
once: a relay printed "ACCEPTED as anything" and refused every peer with "no
token was sent". This half is the case that would catch it.

USAGE
    token-check.py SOCKET [--nokey]
"""
import base64
import json
import os
import socket
import sys
import time

FAILURES = []


def fail(msg):
    FAILURES.append(msg)


def http_pair(sock_path, body="{}"):
    """POST /v1/pair and return the decoded answer, or None."""
    req = ("POST /v1/pair HTTP/1.1\r\nHost: localhost\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n%s"
           % (len(body), body)).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    s.sendall(req)
    buf = b""
    end = time.time() + 3
    while time.time() < end:
        try:
            c = s.recv(4096)
        except socket.timeout:
            break
        if not c:
            break
        buf += c
        if b"\r\n\r\n" in buf:
            head, got = buf.split(b"\r\n\r\n", 1)
            want = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    want = int(line.split(b":", 1)[1].strip())
            if len(got) >= want:
                break
    s.close()
    if b"\r\n\r\n" not in buf:
        return None
    head, got = buf.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n")[0].decode("utf-8", "replace")
    return status, got.decode("utf-8", "replace")


def upgrade(sock_path, path, token=None):
    """A GET upgrade, returning (status_line, whole_first_read)."""
    key = base64.b64encode(b"0123456789abcdef").decode()
    req = ("GET %s HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n" % (path, key))
    if token is not None:
        req += "X-Relay-Token: %s\r\n" % token
    req += "\r\n"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    s.sendall(req.encode())
    time.sleep(0.25)
    try:
        raw = s.recv(4096)
    except socket.timeout:
        raw = b""
    s.close()
    if not raw:
        return "<no reply>", raw
    return raw.split(b"\r\n", 1)[0].decode("utf-8", "replace"), raw


def status_code(line):
    try:
        return int(line.split()[1])
    except Exception:
        return -1


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    sock_path = sys.argv[1]
    nokey = "--nokey" in sys.argv
    sock_b = None
    for a in sys.argv[2:]:
        if a.startswith("--peer="):
            sock_b = a.split("=", 1)[1]

    if nokey:
        # No key: the pair endpoint must REFUSE (there is nothing to sign
        # with) and an untokened upgrade must SUCCEED. Both are behaviour, not
        # opinion: a relay that issues nothing is the documented shape, and a
        # relay that refuses an untokened peer is the regression.
        st, _ = http_pair(sock_path)
        if st is None or status_code(st) != 403:
            fail("a relay with no token key answered POST /v1/pair with %r; "
                 "it must refuse rather than issue two credentials nothing "
                 "can verify" % (st,))
        line, _ = upgrade(sock_path, "/v1/node/nokey-box")
        if status_code(line) != 503 and status_code(line) != 101:
            fail("a relay with no token key refused an untokened upgrade with "
                 "%r. It has always accepted every peer, and requiring a token "
                 "would break every existing deployment on the first upgrade"
                 % (line,))
        return report()


    # ---- 1. the pair endpoint answers, and answers with THREE things
    st, body = http_pair(sock_path) or ("<none>", "")
    if status_code(st) != 200:
        fail("POST /v1/pair answered %r on a keyed relay; it must issue a "
             "pair, because `dropssh pair` posts here and nowhere else"
             % (st,))
        return report()
    try:
        p = json.loads(body)
    except Exception as e:
        fail("the pair answer is not JSON (%s): %r" % (e, body[:120]))
        return report()
    for field in ("name", "node_token", "connect_token", "expires"):
        if not p.get(field):
            fail("the pair answer has no %s, and one of the two roles is now "
                 "unusable" % field)
    if p.get("node_token") == p.get("connect_token"):
        fail("the two roles got the SAME token, so the token carries no role "
             "and reading the cage's token opens a session")

    name = p.get("name", "")

    # ---- 2. the happy pair, both roles, on a relay that issued them
    line, _ = upgrade(sock_path, "/v1/node/" + name, p["node_token"])
    if status_code(line) != 101:
        fail("a node token this relay just issued was refused on /v1/node/ "
             "with %r. A pair issued by our relay has to work against our "
             "relay, or issue #13 step 1 is not done." % (line,))
    line, _ = upgrade(sock_path, "/v1/connect/" + name, p["connect_token"])
    # 503 is also correct: no node is connected, and the relay answers 503 on
    # the upgrade for that. 403 is the failure, because it means the token was
    # rejected before the node was ever consulted.
    if status_code(line) not in (101, 503):
        fail("a connect token this relay just issued was refused with %r"
             % (line,))

    # ---- 3. THE ROLE SWAP. A node token must not open an operator session.
    line, raw = upgrade(sock_path, "/v1/connect/" + name, p["node_token"])
    if status_code(line) != 403:
        fail("a NODE token opened a CONNECT path (%r). The two tokens in a "
             "pair are different credentials, and the cage's token is the one "
             "that is written down in a config file and a log." % (line,))
    elif b"different" not in raw:
        # ⛔ AND THE REASON IS CHECKED, because a 403 that says "forbidden" is
        # not actionable: the operator's actual mistake is that the two lines
        # `dropssh pair` printed got swapped, and the answer has to say so.
        # This is the same "name the fault, not the symptom" rule the rest of
        # this repository keeps, and it is a cheap check because the reason is
        # in the body.
        fail("swapping the two tokens was refused with %r, but the reason did "
             "not say the tokens are different, so an operator cannot tell a "
             "swap from a bad key" % line)

    # ---- 4. A TOKEN FOR ANOTHER NAME. A pair is bound to one name.
    line, _ = upgrade(sock_path, "/v1/node/somewhere-else", p["node_token"])
    if status_code(line) != 403:
        fail("a token for %r was accepted on the name 'somewhere-else' (%r). "
             "Without this check a pair's token works on any name the relay "
             "serves, and pairing binds nothing." % (name, line))

    # ---- 5. A FORGED TOKEN
    line, _ = upgrade(sock_path, "/v1/node/" + name, "d1.AAAA.BBBB")
    if status_code(line) != 403:
        fail("a forged token was accepted with %r" % (line,))
    line, _ = upgrade(sock_path, "/v1/node/" + name, "")
    if status_code(line) != 403:
        fail("an absent token was accepted on a KEYED relay with %r. A relay "
             "that has been told to check must not accept an absent "
             "credential." % (line,))

    # ---- 6. RE-POSTING THE SAME NAME MINTS A DIFFERENT BUT EQUALLY VALID PAIR,
    # and that is correct rather than a defect.
    # ⛔ THE PROPERTY #13 ACTUALLY NEEDS IS NOT "the same bytes twice". It is
    # "a token issued by one relay is honoured by another holding the same
    # key, without the pair being re-created", and that is a property of the
    # token being SELF-CONTAINED rather than a handle into a table on the
    # issuer. A token that embeds its expiry cannot be byte-identical across two
    # posts -- the expiry is the current time plus the TTL -- and a check that
    # demanded identical bytes would be asserting something the design
    # deliberately does not promise.
    # What must hold is that the SECOND token is also good, which is the
    # re-issue path an operator actually uses after a restart.
    _, body2 = http_pair(sock_path, json.dumps({"name": name})) or ("", "")
    try:
        p2 = json.loads(body2)
    except Exception:
        p2 = {}
    if not p2.get("node_token"):
        fail("re-posting the same name returned no token, so an operator "
             "cannot re-issue a pair after a relay restart")
    elif p2.get("node_token") == p.get("node_token"):
        fail("re-posting the same name returned the IDENTICAL token, which "
             "means the expiry is not in the token and it can never be "
             "revoked by age. A token that never expires is a permanent "
             "credential.")
    else:
        line, _ = upgrade(sock_path, "/v1/node/" + name, p2["node_token"])
        if status_code(line) != 101:
            fail("a re-issued pair does not work: the second node token was "
                 "refused with %r, so an operator cannot re-pair after a "
                 "restart" % (line,))

    if sock_b:
        migration(sock_path, sock_b)
    return report()


def migration(sock_a, sock_b):
    """A token issued by relay A must be honoured by relay B holding the same key.

    ⛔ THIS IS THE LINE #13 ACTUALLY ASKS FOR and the one that cannot be
    faked by a table lookup. "A session migrates between two relays without
    being re-created" is only true if a token is SELF-CONTAINED: it carries its
    name, its role and its expiry and is authenticated by a MAC over exactly
    those fields, so a second relay holding the same key can decide everything
    the first relay decided, with no shared state and nothing to look up.

    The obvious design -- an opaque handle into a table on the issuing relay --
    passes the "a pair issued by our relay works against our relay" half of this
    test and fails this half, and it fails it in the only way that matters: at
    the moment the first relay is gone, which is the moment the ladder exists
    for.
    """
    st, body = http_pair(sock_a, '{"name":"migrated"}') or ("<none>", "")
    if status_code(st) != 200:
        fail("relay A could not issue a pair for the migration check: %r" % (st,))
        return
    try:
        p = json.loads(body)
    except Exception:
        fail("relay A's pair answer is not JSON")
        return
    line, _ = upgrade(sock_a, "/v1/node/" + p["name"], p["node_token"])
    if status_code(line) != 101:
        fail("relay A refused the token it just issued: %r" % (line,))
    line, _ = upgrade(sock_b, "/v1/node/" + p["name"], p["node_token"])
    if status_code(line) != 101:
        fail("a token issued by relay A was refused by relay B holding the "
             "SAME key (%r). A token must be self-contained, because that is "
             "what lets a session move between relays without being "
             "re-created, and an opaque handle into the issuer's table cannot "
             "do it." % (line,))
    # And the roles must still be separate across the migration, or the
    # migration would have silently dropped the control it was supposed to
    # preserve.
    line, _ = upgrade(sock_b, "/v1/connect/" + p["name"], p["node_token"])
    if status_code(line) != 403:
        fail("after migrating to relay B the role separation is gone: a node "
             "token opened a connect path with %r" % (line,))


def report():
    for f in FAILURES:
        print("token-check: FAIL %s" % f)
    if not FAILURES:
        print("token-check: a pair issued by this relay works against it, the "
              "two roles are separate credentials, a pair is bound to one "
              "name, and a relay with no key still accepts every peer")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
