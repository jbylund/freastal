"""What the TLS read path does to read_buf.

test_tls.py covers the *write* side's buffer boundaries thoroughly and the read
side barely at all: every request it sends is a ~60-byte GET.  These tests push
plaintext into read_buf until it is full, which is where the encrypted path
stops resembling the plaintext one.

The plaintext path bounds each read by the free space in read_buf, so a client
that pipelines faster than the server answers simply backs up in the socket.
The encrypted path cannot bound a read that way -- the plaintext size is not
known until after decryption -- and closes the connection instead.  These tests
say which of those two behaviours each situation actually gets.
"""

import hashlib
import socket
import ssl
import subprocess
import sys
import time

import pytest
from test_tls import (  # noqa: F401  (certpair is used as a fixture)
    _read_one_response,
    certpair,
    free_port,
    tls_context,
)

# A request the server answers with a fingerprint of what it received, so a
# response can be matched to the request that produced it.
APP_SRC = r"""
import hashlib
import sys
PROTO = sys.argv[1]
PORT = int(sys.argv[2])
CERT, KEY = sys.argv[3], sys.argv[4]
import freastal

_cache = {}

def body_for(n):
    b = _cache.get(n)
    if b is None:
        seed = hashlib.sha256(str(n).encode()).digest()
        b = (seed * (n // 32 + 1))[:n]
        _cache[n] = b
    return b

def reply(tag, body):
    return ("%s:%d:%s" % (tag, len(body), hashlib.sha1(body).hexdigest())).encode()

def route(path, body):
    # /n/<size>  -> a response body of <size> bytes
    # /p/<tag>   -> a fingerprint of the request body
    if path.startswith("/n/"):
        try:
            n = max(0, min(4000000, int(path.rsplit("/", 1)[-1])))
        except ValueError:
            n = 0
        return body_for(n)
    if path.startswith("/p/"):
        return reply(path.rsplit("/", 1)[-1], body)
    return b"?"

if PROTO == "asgi":
    async def app(scope, receive, send):
        body = b""
        if scope["method"] == "POST":
            body = (await receive()).get("body", b"")
        out = route(scope["path"], body)
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [[b"content-type", b"application/octet-stream"]],
        })
        await send({"type": "http.response.body", "body": out})

    freastal.serve_asgi(app, host="127.0.0.1", port=PORT, workers=1,
                        reuse_port=False, certfile=CERT, keyfile=KEY)
else:
    def app(environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(length) if length else b""
        out = route(environ["PATH_INFO"], body)
        start_response("200 OK", [
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", str(len(out))),
        ])
        return [out]

    freastal.serve(app, host="127.0.0.1", port=PORT, workers=1,
                   reuse_port=False, certfile=CERT, keyfile=KEY)
"""

READ_BUF_SIZE = 16 * 1024


def expected_body(n):
    seed = hashlib.sha256(str(n).encode()).digest()
    return (seed * (n // 32 + 1))[:n]


def fingerprint(tag, body):
    return f"{tag}:{len(body)}:{hashlib.sha1(body).hexdigest()}".encode()


def post(tag, nbody, pad=b"x"):
    """A complete POST whose wire form is exactly what it looks like."""
    body = (pad * nbody)[:nbody]
    head = (
        f"POST /p/{tag} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {nbody}\r\n\r\n"
    ).encode()
    return head + body, body


def get(path):
    return f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()


def start(proto, certs):
    cert, key = certs
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-c", APP_SRC, proto, str(port), cert, key],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 25
    while time.time() < deadline:
        if proc.poll() is not None:
            pytest.skip(f"{proto} server exited; build probably lacks TLS")
        try:
            with (
                socket.create_connection(("127.0.0.1", port), timeout=1) as raw,
                tls_context().wrap_socket(raw, server_hostname="localhost") as s,
            ):
                s.sendall(get("/n/1"))
                _read_one_response(s, b"")
            return proc, port
        except (OSError, ssl.SSLError, AssertionError):
            time.sleep(0.25)
    proc.kill()
    pytest.skip(f"{proto} server never became reachable")


@pytest.fixture(scope="module", params=["wsgi", "asgi"])
def echo_tls_server(request, certpair):  # noqa: F811
    proc, port = start(request.param, certpair)
    yield request.param, port
    proc.kill()
    proc.wait(timeout=10)


def connect(port, timeout=20):
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    return tls_context().wrap_socket(raw, server_hostname="localhost")


def expect_response(sock, buf, what):
    """_read_one_response, but saying which response went missing.

    Every way this path fails looks the same from the client -- the server
    stops talking -- so the useful half of the report is how far it got.
    """
    try:
        return _read_one_response(sock, buf)
    except (AssertionError, OSError, ssl.SSLError) as exc:
        raise AssertionError(f"no response for {what}: {exc}") from None


# ---------------------------------------------------------------------------
# The defect: a read that lands on top of an already-buffered request.
# ---------------------------------------------------------------------------


def test_large_read_on_top_of_a_buffered_request(echo_tls_server):
    """Two legal requests, neither anywhere near READ_BUF_SIZE, that overlap
    in read_buf.

    The first request's body is deliberately left incomplete, which is what
    keeps the read armed with read_len non-zero and no response in flight.
    The second flush finishes it and pipelines another request behind it.
    Their combined 17125 bytes exceed the 16384-byte read_buf even though
    each request on its own fits with room to spare -- which on the plaintext
    path just means the socket backs up for a moment.
    """
    _proto, port = echo_tls_server
    req_a, body_a = post("a", 10000)
    req_b, body_b = post("b", 7000)
    assert len(req_a) < READ_BUF_SIZE
    assert len(req_b) < READ_BUF_SIZE

    split = len(req_a) - 1000
    assert split + len(req_b) + 1000 > READ_BUF_SIZE, "must overflow read_buf"

    with connect(port) as s:
        s.sendall(req_a[:split])
        time.sleep(0.3)  # let the server buffer it and go back to waiting
        s.sendall(req_a[split:] + req_b)

        buf = b""
        body, buf = expect_response(s, buf, "request a")
        assert body == fingerprint("a", body_a)
        body, buf = expect_response(s, buf, "request b")
        assert body == fingerprint("b", body_b)


# ---------------------------------------------------------------------------
# Either side of the read_buf boundary, for a single request.
# ---------------------------------------------------------------------------


def test_request_exactly_filling_read_buf(echo_tls_server):
    """A request whose wire form is exactly READ_BUF_SIZE bytes.

    It also spans two reads at the ciphertext level: one 16384-byte plaintext
    record is 16411 bytes on the wire and tls_enc holds 16384, so picotls
    buffers a partial record across the first read and emits all 16384 bytes
    of plaintext on the second.
    """
    _proto, port = echo_tls_server
    head_len = len(post("f", 0)[0])
    nbody = READ_BUF_SIZE - head_len
    # Content-Length grew a digit or two; settle it by construction.
    while True:
        req, body = post("f", nbody)
        if len(req) == READ_BUF_SIZE:
            break
        nbody -= len(req) - READ_BUF_SIZE
    with connect(port) as s:
        s.sendall(req)
        got, rest = expect_response(s, b"", "the buffer-sized request")
        assert got == fingerprint("f", body)
        assert rest == b""


def test_request_larger_than_read_buf_is_rejected(echo_tls_server):
    """One byte past the buffer must be refused, never truncated.

    Truncation would hand the application a short body and answer 200, which
    is the one outcome worse than dropping the connection.
    """
    _proto, port = echo_tls_server
    req, _body = post("g", READ_BUF_SIZE + 4096)
    assert len(req) > READ_BUF_SIZE
    with connect(port) as s:
        try:
            s.sendall(req)
            got, _rest = _read_one_response(s, b"")
        except (OSError, ssl.SSLError, AssertionError):
            return  # refused, which is the expected outcome
        pytest.fail(f"oversized request was answered with {got!r}")


# ---------------------------------------------------------------------------
# The invariant a fix must not break: responses never interleave.
# ---------------------------------------------------------------------------


def _stalled_pipeline(port, first, rest, sizes):
    """Send `first`, let its response fill the socket, then send `rest`."""
    with connect(port, timeout=30) as s:
        s.sendall(first)
        time.sleep(0.5)  # the big response is now queued in libuv, unread
        s.sendall(rest)
        buf = b""
        out = []
        for what in sizes:
            body, buf = expect_response(s, buf, what)
            out.append(body)
        assert buf == b""
        return out


def test_pipelined_request_arriving_mid_response(echo_tls_server):
    """A request that arrives while a response is still draining is answered
    after it, and the two never interleave on the wire."""
    _proto, port = echo_tls_server
    big = 2_000_000
    req_b, body_b = post("m", 500)
    out = _stalled_pipeline(port, get(f"/n/{big}"), req_b, ["the 2MB response", "m"])
    assert out[0] == expected_body(big)
    assert out[1] == fingerprint("m", body_b)


def test_pipelined_burst_overflowing_read_buf_mid_response(echo_tls_server):
    """The same, but the burst behind the in-flight response is larger than
    read_buf, so the read cannot simply accumulate it.

    On a server that stops reading during a response this is free: the burst
    waits in the socket.  It is the case that has to keep working once the
    read stays armed.
    """
    _proto, port = echo_tls_server
    big = 2_000_000
    tags = ["b0", "b1", "b2", "b3", "b4"]
    reqs, bodies = [], []
    for t in tags:
        r, b = post(t, 6000)
        reqs.append(r)
        bodies.append(b)
    assert sum(len(r) for r in reqs) > READ_BUF_SIZE

    out = _stalled_pipeline(
        port, get(f"/n/{big}"), b"".join(reqs), ["the 2MB response", *tags]
    )
    assert out[0] == expected_body(big)
    for i, t in enumerate(tags):
        assert out[i + 1] == fingerprint(t, bodies[i]), t


def test_connection_survives_a_read_buf_sized_pipeline(echo_tls_server):
    """Pipelined POSTs whose total is several times read_buf, with no big
    response stalling anything -- just a client that writes faster than the
    server answers."""
    _proto, port = echo_tls_server
    tags = [f"s{i}" for i in range(8)]
    reqs, bodies = [], []
    for t in tags:
        r, b = post(t, 5000)
        reqs.append(r)
        bodies.append(b)
    assert sum(len(r) for r in reqs) > 2 * READ_BUF_SIZE

    with connect(port, timeout=30) as s:
        s.sendall(b"".join(reqs))
        buf = b""
        for i, t in enumerate(tags):
            body, buf = expect_response(s, buf, t)
            assert body == fingerprint(t, bodies[i]), t
        assert buf == b""


def test_keep_alive_after_an_overflowing_pipeline(echo_tls_server):
    """The connection is still usable once the backlog has drained."""
    _proto, port = echo_tls_server
    reqs, bodies, tags = [], [], [f"k{i}" for i in range(6)]
    for t in tags:
        r, b = post(t, 4000)
        reqs.append(r)
        bodies.append(b)
    with connect(port, timeout=30) as s:
        s.sendall(b"".join(reqs))
        buf = b""
        for i, t in enumerate(tags):
            body, buf = expect_response(s, buf, t)
            assert body == fingerprint(t, bodies[i]), t
        for n in (100, 12000, 0):
            s.sendall(get(f"/n/{n}"))
            body, buf = expect_response(s, buf, f"GET /n/{n}")
            assert body == expected_body(n), n
        assert buf == b""
