"""TLS 1.3, for both protocols.

There was no TLS coverage at all before this, which is how ASGI came to have
no certfile/keyfile parameter and how the ASGI scheme came to be reported as
"http" on a TLS connection.

Skipped when the extension was built without picotls (no OpenSSL headers at
build time), detected by the handshake failing rather than by a build flag,
since the module exposes none.
"""

import contextlib
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

import pytest

BODY = b"tls-body"

APP_SRC = r"""
import sys
PROTO = sys.argv[1]
PORT = int(sys.argv[2])
CERT, KEY = sys.argv[3], sys.argv[4]
import freastal

BODY = b"tls-body"

if PROTO == "asgi":
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                [b"content-type", b"text/plain"],
                [b"x-scheme", scope.get("scheme", "?").encode()],
            ],
        })
        await send({"type": "http.response.body", "body": BODY})

    freastal.serve_asgi(app, host="127.0.0.1", port=PORT, workers=1,
                        reuse_port=False, certfile=CERT, keyfile=KEY)
else:
    def app(environ, start_response):
        start_response("200 OK", [
            ("Content-Type", "text/plain"),
            ("X-Scheme", environ.get("wsgi.url_scheme", "?")),
        ])
        return [BODY]

    freastal.serve(app, host="127.0.0.1", port=PORT, workers=1,
                   reuse_port=False, certfile=CERT, keyfile=KEY)
"""


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# macOS ships LibreSSL as `openssl`.  It mints a certificate fine, but its
# s_client refuses -groups outright ("Failed to set groups") and does not print
# the -msg transcript the key-exchange assertions read, so those tests failed
# rather than skipped on any dev machine that had not put a real OpenSSL first
# on PATH.  Prefer a real OpenSSL wherever one is installed alongside it, so the
# tests actually run there; FREASTAL_OPENSSL overrides the search.
_OPENSSL_PREFIXES = (
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
)


def _is_real_openssl(path):
    """True when `path version` reports OpenSSL rather than LibreSSL."""
    try:
        proc = subprocess.run(
            [path, "version"], capture_output=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.stdout.startswith(b"OpenSSL")


def _resolve_openssl():
    """Return (an openssl to mint certs with, a real OpenSSL or None).

    FREASTAL_OPENSSL pins the binary outright, so a machine with only LibreSSL
    can be reproduced on one that also has OpenSSL.
    """
    override = os.environ.get("FREASTAL_OPENSSL")
    if override:
        candidates = [override]
    else:
        candidates = [shutil.which("openssl")]
        candidates += [p for p in _OPENSSL_PREFIXES if os.path.exists(p)]
    candidates = [c for c in candidates if c]
    real = next((c for c in candidates if _is_real_openssl(c)), None)
    return (candidates[0] if candidates else None), real


OPENSSL, OPENSSL_REAL = _resolve_openssl()


@pytest.fixture(scope="module")
def certpair():
    if OPENSSL is None:
        pytest.skip("openssl not available to mint a test certificate")
    d = tempfile.mkdtemp()
    cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    subprocess.run(
        [
            OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-keyout",
            key,
            "-out",
            cert,
            "-subj",
            "/CN=localhost",
        ],
        capture_output=True,
        check=True,
    )
    yield cert, key
    shutil.rmtree(d, ignore_errors=True)


def tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def start(proto, certpair):
    cert, key = certpair
    port = free_port()
    # Deliberately not a context manager: Popen writes to this for the life
    # of the server and it is read after the process exits.
    errf = tempfile.NamedTemporaryFile("w+", delete=False)  # noqa: SIM115
    proc = subprocess.Popen(
        [sys.executable, "-c", APP_SRC, proto, str(port), cert, key],
        stdout=subprocess.DEVNULL,
        stderr=errf,
    )

    def server_stderr():
        errf.flush()
        with open(errf.name) as f:
            return f.read()

    deadline = time.time() + 25
    while time.time() < deadline:
        if proc.poll() is not None:
            err = server_stderr()
            # Distinguish "this build has no TLS" (skip) from "the API does not
            # take a certificate" (a real failure - that is the feature).
            if "unexpected keyword argument" in err or "TypeError" in err:
                pytest.fail(
                    f"{proto}: serve API rejected certfile/keyfile - TLS is not "
                    f"supported for this protocol:\n{err[-500:]}"
                )
            pytest.skip(
                f"{proto} server exited; build probably lacks TLS "
                f"support:\n{err[-300:]}"
            )
        try:
            conn = http.client.HTTPSConnection(
                "127.0.0.1", port, context=tls_context(), timeout=1
            )
            conn.request("GET", "/")
            conn.getresponse().read()
            conn.close()
            return proc, port
        except (OSError, ssl.SSLError, http.client.HTTPException):
            time.sleep(0.25)
    # Still running, but never answered.  That is not "this build has no TLS"
    # -- a build without it exits at startup and is caught above -- it is a
    # server that came up and does not serve, which every one of these tests
    # would otherwise report as a skip and CI would read as green.
    still_running = proc.poll() is None
    err = server_stderr()
    proc.kill()
    if not still_running:
        pytest.skip(f"{proto} server exited; build probably lacks TLS:\n{err[-300:]}")
    pytest.fail(f"{proto} over TLS came up but never answered:\n{err[-500:]}")


@pytest.fixture(scope="module", params=["wsgi", "asgi"])
def tls_server(request, certpair):
    proc, port = start(request.param, certpair)
    yield request.param, port
    proc.kill()
    proc.wait(timeout=10)


def test_tls_request_succeeds(tls_server):
    _proto, port = tls_server
    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=5
    )
    conn.request("GET", "/")
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    assert resp.status == 200
    assert body == BODY


def test_negotiates_tls_1_3(tls_server):
    _proto, port = tls_server
    with (
        socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
        tls_context().wrap_socket(raw, server_hostname="localhost") as s,
    ):
        assert s.version() == "TLSv1.3", s.version()


def test_scheme_is_https_over_tls(tls_server):
    """A framework builds absolute URLs from this; http over TLS means
    http:// links and redirect loops."""
    _proto, port = tls_server
    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=5
    )
    conn.request("GET", "/")
    resp = conn.getresponse()
    resp.read()
    conn.close()
    assert resp.getheader("X-Scheme") == "https"


def test_keep_alive_reuse_over_tls(tls_server):
    _proto, port = tls_server
    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=5
    )
    for _ in range(3):
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == BODY
    conn.close()


def test_plain_http_still_reports_http_scheme():
    """Guard against fixing the TLS scheme by hard-coding https everywhere."""
    port = free_port()
    src = APP_SRC.replace("certfile=CERT, keyfile=KEY", "certfile=None, keyfile=None")
    proc = subprocess.Popen(
        [sys.executable, "-c", src, "asgi", str(port), "x", "y"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                conn.request("GET", "/")
                resp = conn.getresponse()
                resp.read()
                conn.close()
                assert resp.getheader("X-Scheme") == "http"
                return
            except OSError:
                time.sleep(0.25)
        pytest.fail("plaintext server never became reachable")
    finally:
        proc.kill()
        proc.wait(timeout=10)


# --------------------------------------------------------------------------
# Response sizes across the TLS write path's buffer boundaries.
#
# The encrypted response is built a record at a time into a chain of recycled
# blocks, one uv_write iovec each, and small responses are coalesced into a
# single TLS record by appending the body to resp_hdr.  Both of those have size
# thresholds, and both reuse memory across requests on a connection, so the
# interesting cases are: bodies either side of every threshold, and several of
# them down one connection.
# --------------------------------------------------------------------------

SIZED_APP_SRC = r"""
import hashlib
import json
import sys
PROTO = sys.argv[1]
PORT = int(sys.argv[2])
CERT, KEY = sys.argv[3], sys.argv[4]
import freastal
from freastal._freastal import tls_buffer_stats

_cache = {}

def body_for(n):
    b = _cache.get(n)
    if b is None:
        seed = hashlib.sha256(str(n).encode()).digest()
        b = (seed * (n // 32 + 1))[:n]
        _cache[n] = b
    return b

def size_of(path):
    try:
        return max(0, min(4000000, int(path.rsplit("/", 1)[-1])))
    except ValueError:
        return 0

if PROTO == "asgi":
    async def app(scope, receive, send):
        if scope["path"] == "/stats":
            body = json.dumps(tls_buffer_stats()).encode()
        else:
            body = body_for(size_of(scope["path"]))
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [[b"content-type", b"application/octet-stream"]],
        })
        await send({"type": "http.response.body", "body": body})

    freastal.serve_asgi(app, host="127.0.0.1", port=PORT, workers=1,
                        reuse_port=False, certfile=CERT, keyfile=KEY)
else:
    def app(environ, start_response):
        if environ["PATH_INFO"] == "/stats":
            body = json.dumps(tls_buffer_stats()).encode()
        else:
            body = body_for(size_of(environ["PATH_INFO"]))
        start_response("200 OK", [
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", str(len(body))),
        ])
        return [body]

    freastal.serve(app, host="127.0.0.1", port=PORT, workers=1,
                   reuse_port=False, certfile=CERT, keyfile=KEY)
"""


def expected_body(n):
    seed = hashlib.sha256(str(n).encode()).digest()
    return (seed * (n // 32 + 1))[:n]


def start_sized(proto, certpair):
    cert, key = certpair
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-c", SIZED_APP_SRC, proto, str(port), cert, key],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 25
    while time.time() < deadline:
        if proc.poll() is not None:
            pytest.skip(f"{proto} sized server exited; build probably lacks TLS")
        try:
            conn = http.client.HTTPSConnection(
                "127.0.0.1", port, context=tls_context(), timeout=1
            )
            conn.request("GET", "/n/1")
            conn.getresponse().read()
            conn.close()
            return proc, port
        except (OSError, ssl.SSLError, http.client.HTTPException):
            time.sleep(0.25)
    # Still running, but never answered.  That is not "this build has no TLS"
    # -- a build without it exits at startup and is caught above -- it is a
    # server that came up and does not serve, which every one of these tests
    # would otherwise report as a skip and CI would read as green.
    still_running = proc.poll() is None
    proc.kill()
    if not still_running:
        pytest.skip(f"{proto} sized server exited; build probably lacks TLS")
    pytest.fail(f"{proto} sized server came up but never answered")


@pytest.fixture(scope="module", params=["wsgi", "asgi"])
def sized_tls_server(request, certpair):
    proc, port = start_sized(request.param, certpair)
    yield request.param, port
    proc.kill()
    proc.wait(timeout=10)


# 0 and 1 bracket the empty-body path; 8000-8300 straddles the 8KB resp_hdr
# coalescing limit; 16383-16385 straddles the one-record limit.
#
# The rest straddle block boundaries.  A block holds 16896 bytes of ciphertext
# and a maximal record is 16406, so the first block carries the response
# header's record, one full body record, and a few hundred bytes of a second;
# every block after it holds one record.  Where exactly a block ends therefore
# depends on how long this app's response header is, which is why the sizes
# come in adjacent triples rather than as one number per boundary.
# 65536 needs four body records, 100000 seven.
# fmt: off
BOUNDARY_SIZES = [
    0, 1, 63, 64, 1000,
    8000, 8050, 8060, 8061, 8062, 8063, 8064, 8100, 8191, 8192, 8193, 8300,
    12000, 16000, 16383, 16384, 16385, 16737, 16738, 16739, 16740, 16895, 16896, 16897,
    20000, 33000, 33235, 33236, 33237, 33238, 40000, 49152, 65535, 65536, 65537, 100000,
]
# fmt: on


def test_body_sizes_across_buffer_boundaries(sized_tls_server):
    """One connection, every interesting size, in order.

    Reusing the connection is the point: the encryption block is recycled, so a
    size that is mishandled leaves its damage on the *next* response.
    """
    _proto, port = sized_tls_server
    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=15
    )
    try:
        for n in BOUNDARY_SIZES:
            conn.request("GET", f"/n/{n}")
            resp = conn.getresponse()
            body = resp.read()
            assert resp.status == 200, n
            assert body == expected_body(n), (
                f"size {n}: got {len(body)} bytes, wanted {n}"
            )
    finally:
        conn.close()


def test_alternating_sizes_reuse_one_connection(sized_tls_server):
    """Alternate over/under every threshold so consecutive requests keep
    changing how many blocks the write path takes from the pool.

    A response spanning several blocks returns all of them at once, so a
    one-block response served immediately afterwards is handed a block that
    was part of a chain a moment ago.
    """
    _proto, port = sized_tls_server
    sizes = [100, 12000, 200, 40000, 8192, 0, 16384, 500, 65536, 1, 100000, 16739]
    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=15
    )
    try:
        for n in sizes * 3:
            conn.request("GET", f"/n/{n}")
            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.read() == expected_body(n), n
    finally:
        conn.close()


def _read_exactly(sock, n):
    chunks = []
    got = 0
    while got < n:
        b = sock.recv(min(65536, n - got))
        if not b:
            raise AssertionError(f"connection closed after {got} of {n} bytes")
        chunks.append(b)
        got += len(b)
    return b"".join(chunks)


def _read_full_response(sock, buf):
    """Pull one complete HTTP/1.1 response out of sock as (head, body, rest).

    `head` includes the blank line that ends it, so len(head) + len(body) is
    exactly the plaintext the server encrypted for this response - which is
    what decides its record framing.
    """
    while b"\r\n\r\n" not in buf:
        b = sock.recv(65536)
        if not b:
            raise AssertionError("connection closed mid-headers")
        buf += b
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = None
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.lower() == b"content-length":
            length = int(value)
    assert length is not None, head
    while len(rest) < length:
        b = sock.recv(65536)
        if not b:
            raise AssertionError("connection closed mid-body")
        rest += b
    return head + b"\r\n\r\n", rest[:length], rest[length:]


def _read_one_response(sock, buf):
    """Pull one complete HTTP/1.1 response out of sock, returning (body, rest)."""
    _head, body, rest = _read_full_response(sock, buf)
    return body, rest


def test_pipelined_requests_over_tls(sized_tls_server):
    """All requests written before any response is read.

    A write buffer that is recycled while uv_write still points into it
    corrupts exactly here and nowhere else - a plain request/response test
    never has two responses close enough together to notice.
    """
    _proto, port = sized_tls_server
    sizes = [500, 12000, 100, 8192, 40000, 64, 16384, 1000]
    request = b"".join(
        f"GET /n/{n} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode() for n in sizes
    )
    with (
        socket.create_connection(("127.0.0.1", port), timeout=20) as raw,
        tls_context().wrap_socket(raw, server_hostname="localhost") as s,
    ):
        s.sendall(request)
        buf = b""
        for n in sizes:
            body, buf = _read_one_response(s, buf)
            assert body == expected_body(n), f"pipelined size {n}"
        assert buf == b""


def test_many_concurrent_tls_connections(sized_tls_server):
    """Several connections with responses in flight at once, which is what
    decides how many encryption blocks the pool has to hand out."""
    _proto, port = sized_tls_server
    conns = []
    try:
        for i in range(16):
            c = http.client.HTTPSConnection(
                "127.0.0.1", port, context=tls_context(), timeout=20
            )
            c.connect()
            conns.append(c)
        sizes = [(i * 997) % 20000 for i in range(len(conns))]
        for c, n in zip(conns, sizes):
            c.request("GET", f"/n/{n}")
        for c, n in zip(conns, sizes):
            resp = c.getresponse()
            assert resp.status == 200
            assert resp.read() == expected_body(n), n
    finally:
        for c in conns:
            c.close()


def test_pipelined_flood_stalls_the_socket(sized_tls_server):
    """Pipeline more than a socket buffer's worth before reading a byte.

    On loopback uv_write nearly always hands the whole response to the kernel
    before it returns, so a buffer recycled one instruction too early is
    invisible.  Backing the socket up is what forces libuv to queue the write
    and keep its pointer into the encryption buffer live across event-loop
    turns, which is the only state in which premature reuse can be observed.
    """
    _proto, port = sized_tls_server
    count, size = 96, 16000
    request = b"".join(
        f"GET /n/{size} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
        for _ in range(count)
    )
    want = expected_body(size)
    with (
        socket.create_connection(("127.0.0.1", port), timeout=30) as raw,
        tls_context().wrap_socket(raw, server_hostname="localhost") as s,
    ):
        s.sendall(request)
        time.sleep(0.5)  # let the server fill and then block on the socket
        buf = b""
        for i in range(count):
            body, buf = _read_one_response(s, buf)
            assert body == want, f"response {i} of {count} came back corrupted"
        assert buf == b""


def test_response_larger_than_the_socket_buffer(sized_tls_server):
    """A single response too big for one write, so libuv keeps the encryption
    buffer alive across several loop turns while draining it."""
    _proto, port = sized_tls_server
    size = 2_000_000
    with (
        socket.create_connection(("127.0.0.1", port), timeout=30) as raw,
        tls_context().wrap_socket(raw, server_hostname="localhost") as s,
    ):
        s.sendall(f"GET /n/{size} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        time.sleep(0.3)
        body, rest = _read_one_response(s, b"")
        assert rest == b""
        assert body == expected_body(size)


def _handshake_over_bio(raw, ctx):
    """Drive a TLS handshake through memory BIOs.

    A wrapped socket gives no control over how writes are framed into
    records; memory BIOs do, which is the only way to put two complete
    records into one segment on purpose.
    """
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    sock = ctx.wrap_bio(incoming, outgoing, server_hostname="localhost")
    while True:
        try:
            sock.do_handshake()
            break
        except ssl.SSLWantReadError:
            pending = outgoing.read()
            if pending:
                raw.sendall(pending)
            incoming.write(raw.recv(65536))
    pending = outgoing.read()
    if pending:
        raw.sendall(pending)
    return sock, incoming, outgoing


class _BioReader:
    """Gives a memory-BIO TLS object the .recv() that _read_one_response wants.

    Every raw byte it pulls off the socket is kept in .ciphertext, so a test
    can inspect the record framing the server chose without decrypting: a TLS
    record's type and length are in the clear.
    """

    def __init__(self, raw, sock, incoming):
        self._raw, self._sock, self._incoming = raw, sock, incoming
        self.ciphertext = bytearray()

    def recv(self, n):
        while True:
            try:
                data = self._sock.read(n)
                if data:
                    return data
            except ssl.SSLWantReadError:
                pass
            chunk = self._raw.recv(65536)
            if not chunk:
                return b""
            self.ciphertext += chunk
            self._incoming.write(chunk)


def _tls_records(blob):
    """Split a captured TLS stream into (content_type, payload_length) pairs."""
    out, i = [], 0
    while i + 5 <= len(blob):
        out.append((blob[i], int.from_bytes(blob[i + 3 : i + 5], "big")))
        i += 5 + out[-1][1]
    assert i == len(blob), f"capture ends {len(blob) - i} bytes into a record"
    return out


def test_two_records_in_one_segment(sized_tls_server):
    """Two pipelined requests the peer flushed separately.

    ptls_receive() returns after one record's worth of application data, so
    a read holding two records needs two calls.  Making only the first
    dropped the second request outright: the server answered once and the
    client waited for a response that was never sent.

    test_pipelined_requests_over_tls cannot catch this - sendall() of eight
    small requests is well under the 16KB record limit, so OpenSSL emits a
    single record and there is no residual to lose.
    """
    _proto, port = sized_tls_server
    sizes = [500, 12000]
    with socket.create_connection(("127.0.0.1", port), timeout=20) as raw:
        sock, incoming, _outgoing = _handshake_over_bio(raw, tls_context())
        records = b""
        for n in sizes:
            sock.write(f"GET /n/{n} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
            records += _outgoing.read()
        raw.sendall(records)  # one segment, two complete records

        raw.settimeout(20)
        reader = _BioReader(raw, sock, incoming)
        buf = b""
        for n in sizes:
            body, buf = _read_one_response(reader, buf)
            assert body == expected_body(n), f"size {n} in coalesced records"


# --- A record fragmented across segments, with a request behind it ------
def _record_stream(sock, outgoing, requests):
    """Encrypt each request separately and return the concatenated records."""
    out = b""
    for req in requests:
        sock.write(req)
        out += outgoing.read()
    return out


def _big_request(total):
    """A POST whose headers and body come to exactly `total` bytes.

    16384 of plaintext is the largest a single TLS record can carry, and it is
    also exactly READ_BUF_SIZE, which is what makes it the interesting size.
    """
    head = b"POST /n/500 HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n\r\n"
    body_len = total
    for _ in range(5):  # settles immediately; the length field barely moves
        body_len = total - len(head % body_len)
    request = (head % body_len) + b"x" * body_len
    assert len(request) == total, len(request)
    return request


def test_split_record_then_pipelined_request(sized_tls_server):
    """A record fragmented across segments, then a pipelined request behind it.

    This is the case that used to drop the connection outright.  picotls
    buffers an incomplete record internally, so the *second* read emits the
    whole 16KB record's plaintext plus the small request that followed it in
    the same segment -- more plaintext than READ_BUF_SIZE -- and the old code
    answered that by closing the socket rather than by pacing the decryption.

    Splitting the first record is what makes it reachable: without the split,
    one read can never emit more plaintext than the ciphertext it took in.
    """
    _proto, port = sized_tls_server
    big = _big_request(16384)
    small = b"GET /n/300 HTTP/1.1\r\nHost: localhost\r\n\r\n"

    with socket.create_connection(("127.0.0.1", port), timeout=20) as raw:
        sock, incoming, outgoing = _handshake_over_bio(raw, tls_context())
        records = _record_stream(sock, outgoing, [big, small])
        # One maximum-sized record followed by a small one.
        assert len(records) > 16384, len(records)

        raw.sendall(records[:16000])  # first record, incomplete
        time.sleep(0.3)  # force a separate read, leaving a partial record
        raw.sendall(records[16000:])  # its tail plus the whole second record

        raw.settimeout(20)
        reader = _BioReader(raw, sock, incoming)
        buf = b""
        body, buf = _read_one_response(reader, buf)
        assert body == expected_body(500), "large request lost"
        body, buf = _read_one_response(reader, buf)
        assert body == expected_body(300), "pipelined request behind it lost"


# --------------------------------------------------------------------------
# What the handshake negotiated, not merely that it completed.
#
# Every test above drives the server with Python's ssl module, which offers
# P-256 and eats a HelloRetryRequest without comment -- so it can never tell
# which groups the server actually knows.  Browsers can: Chrome and Firefox
# list P-256 in supported_groups but send key shares only for X25519MLKEM768
# and X25519.  A server that knows P-256 alone matches no share and answers
# with a HelloRetryRequest: an extra round trip on every new connection,
# invisible to a keep-alive benchmark and to everything above.
#
# These drive `openssl s_client`, the only client here that can be told exactly
# which groups and cipher suites to offer and will print what it exchanged.
# They skip, never fail, when there is no s_client or it is too old for an
# option or a group name.
#
# Two things about detecting the retry are easy to get wrong:
#
#   * P-256 must stay in -groups.  It sets supported_groups as well as the key
#     shares, so `-groups X25519MLKEM768:X25519` leaves a P-256-only server
#     nothing to retry *toward*: it fails the handshake outright rather than
#     paying for a round trip.  That is a real case too, covered separately
#     below, but it is not the browser one.
#   * Grepping for "HelloRetryRequest" finds nothing either way.  A retry is a
#     ServerHello on the wire, distinguished only by a sentinel random, and
#     neither -msg nor -trace ever prints that name.  Counting ClientHellos
#     does work: two means the client had to start over.
# --------------------------------------------------------------------------

S_CLIENT_TIMEOUT = 30

# s_client refuses an option it does not have, or a group name this build does
# not know, before it ever connects.  Both mean "this openssl is too old for
# this assertion", not "the server is wrong".  Compared against a lowercased
# transcript so the match does not hinge on the exact capitalization, which
# has not been checked across releases.
S_CLIENT_UNUSABLE = (
    "call to ssl_conf_cmd",  # e.g. -groups X25519MLKEM768 on OpenSSL < 3.5
    "unknown option",
    "usage: s_client",
)

# A ClientHello as -msg announces it, so cert text mentioning the word cannot
# be miscounted.
_CLIENT_HELLO = re.compile(r"^>>> TLS 1\.3, Handshake .*ClientHello", re.MULTILINE)

# s_client reports the negotiated group two different ways, and which one it
# prints varies by release.  A hybrid KEM appears only in the summary line
# ("Negotiated TLS1.3 group: X25519MLKEM768"), which 3.0 does not print at
# all.  A plain curve appears only as the temp key, and the label differs:
# 3.0.13 says "Server Temp Key: X25519, 253 bits" where 3.6.3 says "Peer Temp
# Key" (with an "ECDH, " prefix for the NIST curves: "ECDH, prime256v1, 256
# bits").  Those are the two releases actually observed -- where in between
# the rename landed is not known, so accept both spellings rather than
# switching on a version.  Miss one and a 3.0 handshake that did negotiate
# X25519 reads as no handshake at all, which is what CI first caught.
_GROUP_LINE = re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)")
_TEMP_KEY_LINE = re.compile(r"(?:Peer|Server) Temp Key:\s*(?:ECDH,\s*)?([^,\n]+)")

GROUP_CASES = [
    ("X25519MLKEM768:X25519:P-256", "X25519MLKEM768"),  # current Chrome/Firefox
    ("X25519:P-256", "X25519"),  # a client with no post-quantum support
]


def s_client(port, args):
    """Run one `openssl s_client` handshake, returning its whole transcript."""
    if OPENSSL is None:
        pytest.skip("openssl s_client not available")
    if OPENSSL_REAL is None:
        pytest.skip(
            f"{OPENSSL} is not OpenSSL; its s_client cannot be told which "
            "groups to offer, nor print what it exchanged"
        )
    proc = subprocess.run(
        [OPENSSL_REAL, "s_client", "-connect", f"127.0.0.1:{port}", *args],
        input=b"",
        capture_output=True,
        timeout=S_CLIENT_TIMEOUT,
        check=False,
    )
    out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    lowered = out.lower()
    for unusable in S_CLIENT_UNUSABLE:
        if unusable in lowered:
            pytest.skip(f"openssl s_client cannot run {' '.join(args)}: {unusable}")
    return out


def negotiated_group(trace):
    m = _GROUP_LINE.search(trace)
    if m is not None and m.group(1) != "<NULL>":
        return m.group(1)
    m = _TEMP_KEY_LINE.search(trace)
    return m.group(1).strip() if m is not None else None


def assert_single_round_trip(trace, groups):
    hellos = len(_CLIENT_HELLO.findall(trace))
    assert hellos == 1, (
        f"-groups {groups}: {hellos} ClientHellos, so the server forced a "
        f"HelloRetryRequest instead of accepting an offered key share"
    )


@pytest.mark.parametrize(("groups", "expected"), GROUP_CASES)
def test_offered_key_share_is_accepted_without_a_retry(tls_server, groups, expected):
    """The direct test for the P-256-only key_exchanges list.

    Every group here is one the client sent a key share for, so a correct
    server picks one and answers in a single round trip.
    """
    _proto, port = tls_server
    trace = s_client(port, ["-groups", groups, "-msg"])
    assert_single_round_trip(trace, groups)
    assert negotiated_group(trace) == expected, (
        f"-groups {groups}: negotiated {negotiated_group(trace)}, wanted {expected}"
    )


@pytest.mark.parametrize("groups", ["X25519MLKEM768:X25519", "X25519"])
def test_handshake_without_p256_in_the_offer(tls_server, groups):
    """A client that offers no P-256 at all must still get a handshake.

    With P-256 absent from supported_groups there is nothing left to retry
    with, so a P-256-only server fails outright rather than merely paying for
    a round trip.
    """
    _proto, port = tls_server
    trace = s_client(port, ["-groups", groups, "-msg"])
    assert_single_round_trip(trace, groups)
    assert negotiated_group(trace) is not None, (
        f"-groups {groups}: no group negotiated - the handshake failed because "
        f"the server supports none of the groups the client offered"
    )


@pytest.mark.parametrize(
    ("ciphersuites", "expected"),
    [
        ("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"),
        ("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"),
    ],
    ids=["client-prefers-aes128", "client-prefers-aes256"],
)
def test_cipher_follows_client_order(tls_server, ciphersuites, expected):
    """Client preference decides the cipher, both ways round.

    ctx.server_cipher_preference is left at 0, so select_cipher() takes the
    first client-offered suite it supports and the order of
    ptls_openssl_cipher_suites does not matter.  That is what lets a phone
    without AES instructions get ChaCha20 instead of paying for AES in
    software.  Anyone "fixing" the server list's apparently-backwards order by
    turning server preference on breaks that, and breaks this.
    """
    _proto, port = tls_server
    out = s_client(port, ["-ciphersuites", ciphersuites])
    line = next((ln for ln in out.splitlines() if ln.startswith("New,")), None)
    assert line is not None, f"s_client never completed a handshake:\n{out[-800:]}"
    assert line.endswith(expected), (
        f"client offered {ciphersuites}; server chose {line!r}, wanted {expected}"
    )


# --------------------------------------------------------------------------
# Orderly shutdown.
#
# A TLS close is announced, not just performed: RFC 8446 6.1 has each side
# send a close_notify alert before dropping the connection, so a peer reading
# to EOF can tell an intended close from an attacker cutting the TCP stream
# short.  freastal used to close the socket and nothing else, which every HTTP
# client tolerates when Content-Length already said the body was complete --
# and which OpenSSL punishes in the one place it can, by refusing to keep a
# session it saw truncated.  That is why the resumption below could not work
# until this did (#57).
#
# Python's ssl module papers over exactly this by default:
# suppress_ragged_eofs=True turns a missing close_notify into a quiet b"".
# These tests turn it off, which makes reaching EOF at all the assertion.
# --------------------------------------------------------------------------

CLOSE_REQUEST = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
HTTP10_REQUEST = b"GET / HTTP/1.0\r\n\r\n"


def _read_to_eof_strictly(port, request):
    """One request, read to EOF on a socket that will not hide a bad close.

    recv() raises ssl.SSLEOFError if the server drops the connection without
    a close_notify, so the return itself is the assertion; the bytes come back
    so the caller can also check the response survived intact.
    """
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    with tls_context().wrap_socket(
        raw, server_hostname="localhost", suppress_ragged_eofs=False
    ) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


@pytest.mark.parametrize(
    ("label", "request_bytes"),
    [("connection-close", CLOSE_REQUEST), ("http-1.0", HTTP10_REQUEST)],
)
def test_close_notify_precedes_the_close(tls_server, label, request_bytes):
    """Both ways an HTTP client asks for the connection to end.

    They are one branch in on_write -- !keep_alive -- but they reach it by
    different routes, a Connection header and an absent one, so both are worth
    stating.  The response has to arrive intact as well as cleanly terminated:
    sending the alert in place of the last of the body would satisfy the EOF
    and serve nobody.
    """
    _proto, port = tls_server
    resp = _read_to_eof_strictly(port, request_bytes)
    assert resp.startswith(b"HTTP/1."), (label, resp[:80])
    assert b" 200 " in resp.split(b"\r\n", 1)[0], (label, resp[:80])
    assert resp.endswith(BODY), (label, resp[-80:])


def test_close_notify_after_a_segmented_response(sized_tls_server):
    """Responses whose encryption spanned one block, a chain of them, and the
    oversized buffer.

    The alert takes a pooled block of its own, and takes it in on_write just
    after that chain went back -- so this is the case where the close path
    reuses a block the response was holding a moment earlier.
    """
    _proto, port = sized_tls_server
    for n in [0, 8, 16384, 65536, 2_000_000, 3_000_000]:
        resp = _read_to_eof_strictly(
            port,
            f"GET /n/{n} HTTP/1.1\r\nHost: localhost\r\n"
            f"Connection: close\r\n\r\n".encode(),
        )
        body = resp.split(b"\r\n\r\n", 1)[1]
        assert body == expected_body(n), (n, len(body))


def test_close_notify_blocks_go_back_to_the_pool(sized_tls_server):
    """The block the alert borrows is released again.

    Leaked here it would leak one per closed connection, which is a shape no
    keep-alive test can see: every other TLS test in this file reuses its
    connection or never asks the server to close one.
    """
    _proto, port = sized_tls_server
    for _ in range(20):
        _read_to_eof_strictly(port, CLOSE_REQUEST)

    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=20
    )
    try:
        st = _stats(conn)
        assert st["blocks_live"] == 0, st
        assert st["bigbufs_live"] == 0, st
    finally:
        conn.close()


def test_a_peer_that_keeps_talking_through_the_close(sized_tls_server):
    """Requests pipelined behind the one that asked for the close.

    The alert costs a loop turn that the bare uv_close() did not, and reading
    is armed across a response, so on_read can now fire on a connection that
    has already said goodbye.  Starting a second response there would put a
    second user on c->write_req while the alert still holds it, so
    tls_send_close_notify() stops reading first.  What the client must see is
    one response and a clean end, not two responses and not a dead server.
    """
    _proto, port = sized_tls_server
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    with tls_context().wrap_socket(
        raw, server_hostname="localhost", suppress_ragged_eofs=False
    ) as sock:
        sock.sendall(
            b"GET /n/16384 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            + b"GET /n/8 HTTP/1.1\r\nHost: localhost\r\n\r\n" * 8
        )
        resp = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            resp += chunk
    assert resp.count(b"HTTP/1.1 200") == 1, resp[:200]
    assert resp.split(b"\r\n\r\n", 1)[1] == expected_body(16384)

    # The server is still serving: a libuv abort on the second write would
    # have taken the whole process with it.
    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=20
    )
    try:
        conn.request("GET", "/n/8")
        assert conn.getresponse().read() == expected_body(8)
        st = _stats(conn)
        assert st["blocks_live"] == 0, st
    finally:
        conn.close()


def _shutdown_was_announced(raw, sock, incoming):
    """Read a memory-BIO session to its end; True if it ended in close_notify.

    Handing the BIO a real EOF is what tells the two endings apart: OpenSSL
    returns b"" when it decrypted a close_notify first, and raises
    ssl.SSLEOFError when the stream merely stopped.  A wrapped socket cannot
    be used here because the test has to inject a raw record of its own.
    """
    eof = False
    while True:
        try:
            if sock.read(65536):
                continue
            return True
        except ssl.SSLEOFError:
            return False
        except ssl.SSLWantReadError:
            if eof:
                return False  # nothing more is coming, and no alert came
        try:
            chunk = raw.recv(65536)
        except OSError:
            chunk = b""  # a reset is an unannounced ending too
        if chunk:
            incoming.write(chunk)
        else:
            incoming.write_eof()
            eof = True


def test_a_broken_record_layer_closes_without_close_notify(sized_tls_server):
    """The deliberate asymmetry: a connection whose TLS state is unusable is
    dropped, not signed off.

    ptls_send_alert() asks only whether the encryption keys exist, so it would
    happily encrypt an alert with a record layer the peer has just proved it
    cannot follow -- an announcement that announces nothing.  A bare close is
    the honest ending, and the guard in tls_read_failed() is what keeps it,
    so this pins it rather than letting it quietly stop mattering.

    Same shape as test_read_failure_while_a_segmented_response_is_writing:
    a well-formed application-data record whose body cannot authenticate.
    """
    _proto, port = sized_tls_server
    for _ in range(3):
        with socket.create_connection(("127.0.0.1", port), timeout=20) as raw:
            sock, incoming, outgoing = _handshake_over_bio(raw, tls_context())
            sock.write(b"GET /n/8 HTTP/1.1\r\nHost: localhost\r\n\r\n")
            raw.sendall(outgoing.read())
            raw.sendall(b"\x17\x03\x03\x00\x20" + os.urandom(32))
            assert not _shutdown_was_announced(raw, sock, incoming)


# --------------------------------------------------------------------------
# Session resumption.
#
# The handshake above is the expensive one: a fresh certificate signature on
# every connection.  A NewSessionTicket lets the next connection skip it, and
# picotls mints one only when ctx.encrypt_ticket is set.  freastal leaves it
# NULL (#29), so a client is given nothing to resume with and every reconnect
# pays for the signature again -- invisible to every test above, and to a
# keep-alive benchmark, which reconnects never.
#
# Python's ssl module drives this rather than s_client, whose -sess_out races
# the ticket: with stdin at EOF it can send close_notify before the ticket
# arrives, and whether it does varies by release.  Reading an HTTP response
# to EOF cannot race it.
#
# Note that an SSLSession object is not the signal.  A TLS 1.3 client always
# has the handshake's own session; what a ticket adds is a non-zero lifetime
# hint and the ability to resume, so those are what get asserted.
# --------------------------------------------------------------------------


def request_over_new_connection(port, ctx, session=None):
    """One request on a connection of its own, read to EOF.

    Returns the session the client came away holding, whether the server
    agreed to resume, and the body bytes.  Reaching EOF is the point: a
    NewSessionTicket arrives after the handshake, so a client that stops
    reading at the end of the response may never see it.
    """
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    with ctx.wrap_socket(raw, server_hostname="localhost", session=session) as sock:
        sock.sendall(CLOSE_REQUEST)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return sock.session, sock.session_reused, b"".join(chunks)


@pytest.mark.xfail(
    strict=True,
    reason="#29: ctx.encrypt_ticket is NULL, so picotls issues no ticket",
)
def test_session_ticket_is_issued_and_resumes(tls_server):
    """A ticket is issued, and offering it back actually resumes.

    Two assertions rather than one because a server can do the first without
    the second: minting tickets it then declines to accept resumes nothing
    and still costs a round of ticket encryption.

    When #29 lands, drop the xfail -- strict, so it will say so by failing.
    """
    _proto, port = tls_server
    # One context for both connections: an SSLSession cannot be offered to a
    # context other than the one that produced it.
    ctx = tls_context()

    session, reused, body = request_over_new_connection(port, ctx)
    assert not reused, "first connection resumed, with nothing yet to resume from"
    assert body.endswith(BODY), body[-200:]
    assert session is not None and session.ticket_lifetime_hint > 0, (
        "no NewSessionTicket was issued, so a returning client has nothing to "
        "resume with and every reconnect repeats the certificate signature"
    )

    _session, resumed, body = request_over_new_connection(port, ctx, session=session)
    assert resumed, "the server issued a ticket and then would not resume from it"
    assert body.endswith(BODY), body[-200:]


# TLS 1.3 caps a record's plaintext at 16KB and frames it with 22 bytes: a
# 5-byte header outside the length field, then the content-type byte and the
# 16-byte AEAD tag inside it.
MAX_RECORD_PLAINTEXT = 16384
RECORD_INNER_OVERHEAD = 17
CONTENT_TYPE_APPDATA = 23


class _RecordCapture:
    """One keep-alive TLS connection, with every record the server sends counted.

    A wrapped socket hides the record framing entirely; memory BIOs do not,
    and _BioReader already keeps every raw byte that arrives.  A TLS record's
    type and length are in the clear, so the framing can be read off the
    capture without decrypting anything.

    Requests go one at a time, so records arrive in response order and each
    response's share of them is settled by plaintext accounting: an
    application-data record carries `length - RECORD_INNER_OVERHEAD` bytes of
    plaintext, and a response's plaintext is exactly its header block plus its
    body.  If those two numbers ever disagree the capture is not describing
    the response, and get() says so rather than reporting a count nobody
    should believe.
    """

    def __init__(self, port, timeout=20):
        self._raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self._sock, incoming, self._outgoing = _handshake_over_bio(
            self._raw, tls_context()
        )
        self._raw.settimeout(timeout)
        self._reader = _BioReader(self._raw, self._sock, incoming)
        self._buf = b""
        self._taken = 0  # records already attributed to an earlier response

    def get(self, path):
        """Send one request, returning (head, body, record plaintext lengths)."""
        self._sock.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        self._raw.sendall(self._outgoing.read())
        head, body, self._buf = _read_full_response(self._reader, self._buf)

        records = _tls_records(bytes(self._reader.ciphertext))
        mine = records[self._taken :]
        self._taken = len(records)

        types = sorted({t for t, _ in mine})
        assert types == [CONTENT_TYPE_APPDATA], (
            f"GET {path}: record content types on the wire were {types}, "
            f"wanted only application data ({CONTENT_TYPE_APPDATA})"
        )
        plaintext = [ln - RECORD_INNER_OVERHEAD for _t, ln in mine]
        assert sum(plaintext) == len(head) + len(body), (
            f"GET {path}: the records carry {sum(plaintext)} bytes of plaintext "
            f"but the response is {len(head) + len(body)} bytes - the capture "
            f"and the response disagree, so no count from it can be trusted"
        )
        return head, body, plaintext

    def close(self):
        self._raw.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _wanted_framing(head_len, body_len):
    """The records a correct server emits for a response of this shape.

    The header and the body are one plaintext stream cut into maximal 16KB
    records.  Not two streams: splitting at the header/body seam buys a second
    record header, a second AEAD pass and a second tag for nothing, and for a
    small response that second record is most of what sending it costs.
    """
    total = head_len + body_len
    return [
        min(MAX_RECORD_PLAINTEXT, total - o)
        for o in range(0, total, MAX_RECORD_PLAINTEXT)
    ]


def _framing_lines(wrong):
    return "\n".join(
        f"  body {n:>7}: {len(got):>3} records {got}\n"
        f"  {'':>12}  {len(want):>3} wanted  {want}  "
        f"(response header was {head_len} bytes)"
        for n, head_len, got, want in wrong
    )


# 0 is the header alone -- no body vector at all.  8191/8192/8193 straddle the
# old RESP_HDR_SIZE coalescing threshold, which used to decide the framing and
# no longer has anything to do with it.  16000 is the largest body here that
# still leaves room for the response header inside one record.
ONE_RECORD_SIZES = [0, 1, 63, 64, 1000, 8000, 8191, 8192, 8193, 8300, 12000, 16000]


@pytest.mark.parametrize("size", ONE_RECORD_SIZES)
def test_one_record_per_response_that_fits_in_one(sized_tls_server, size):
    """A response small enough for a single TLS record must be sent as one.

    This is the whole point of the vectored write path: header and body reach
    picotls as two iovecs of one record, so no size threshold in freastal --
    RESP_HDR_SIZE least of all -- decides how many records a response costs.
    """
    _proto, port = sized_tls_server
    with _RecordCapture(port) as cap:
        head, body, records = cap.get(f"/n/{size}")

    assert body == expected_body(size), f"body {size} came back wrong"
    total = len(head) + len(body)
    assert total <= MAX_RECORD_PLAINTEXT, (
        f"body {size} behind a {len(head)}-byte response header is {total} "
        f"bytes, past the {MAX_RECORD_PLAINTEXT}-byte record limit: this size "
        f"no longer tests what it was picked to test"
    )
    assert records == [total], (
        f"body {size}: the server sent {len(records)} records {records}; the "
        f"whole {total}-byte response fits in one record, so it must be one"
    )


@pytest.mark.parametrize("size", [16385, 20000, 33000, 65536, 100000])
def test_record_boundary_falls_inside_the_body(sized_tls_server, size):
    """Past one record the split lands mid-body, not at the header/body seam.

    The header and the first 16384 - len(header) bytes of the body share the
    first record, so the record boundary falls in the middle of the body
    iovec.  That is the case the vectored send has to get right and the one a
    body-only assertion cannot see: splitting per iovec instead decrypts to
    exactly the same bytes.
    """
    _proto, port = sized_tls_server
    with _RecordCapture(port, timeout=30) as cap:
        head, body, records = cap.get(f"/n/{size}")

    assert body == expected_body(size), f"body {size} came back wrong"
    want = _wanted_framing(len(head), len(body))
    assert records == want, _framing_lines([(size, len(head), records, want)])
    assert records[0] == MAX_RECORD_PLAINTEXT > len(head), (
        f"body {size}: first record is {records[0]} bytes for a {len(head)}-byte "
        f"header, so the server closed the record at the header/body seam "
        f"instead of filling it from the body"
    )


def test_record_framing_across_the_size_sweep(sized_tls_server):
    """Every boundary size, in order, down one keep-alive connection.

    One connection is deliberate twice over.  The encryption blocks are
    recycled, so a size framed wrongly tends to show up on the *next*
    response; and every record here shares one AEAD sequence, so a miscounted
    record would desynchronise it and the rest of the sweep would fail to
    decrypt at all rather than merely miscount.

    Every mismatch is collected before failing: one run then says which sizes
    are wrong, instead of stopping at the first.
    """
    _proto, port = sized_tls_server
    wrong = []
    with _RecordCapture(port, timeout=30) as cap:
        for n in BOUNDARY_SIZES:
            head, body, records = cap.get(f"/n/{n}")
            assert body == expected_body(n), (
                f"size {n}: got {len(body)} bytes of body, wanted {n}"
            )
            want = _wanted_framing(len(head), len(body))
            if records != want:
                wrong.append((n, len(head), records, want))

    assert not wrong, (
        f"{len(wrong)} of {len(BOUNDARY_SIZES)} responses were cut into the "
        f"wrong TLS records:\n" + _framing_lines(wrong)
    )


def test_record_framing_of_a_response_too_large_to_segment(sized_tls_server):
    """Past the per-response block cap the whole response is handed to picotls
    in one call, so it is picotls's own chunking that has to cross the
    header/body boundary rather than freastal's.  Same framing either way.
    """
    _proto, port = sized_tls_server
    size = 2_500_000
    with _RecordCapture(port, timeout=60) as cap:
        head, body, records = cap.get(f"/n/{size}")

    assert body == expected_body(size)
    want = _wanted_framing(len(head), len(body))
    if records != want:
        differs = [i for i, (g, w) in enumerate(zip(records, want)) if g != w]
        pytest.fail(
            f"body {size}: {len(records)} records, wanted {len(want)}; first "
            f"length mismatch at record "
            f"{differs[0] if differs else min(len(records), len(want))}"
        )


def test_many_large_responses_in_flight_at_once(sized_tls_server):
    """Enough multi-block responses outstanding together to make the pool the
    thing under test: every block of every chain is held until its write
    completes, so they cannot be handed out twice."""
    _proto, port = sized_tls_server
    conns = []
    try:
        for _ in range(12):
            c = http.client.HTTPSConnection(
                "127.0.0.1", port, context=tls_context(), timeout=30
            )
            c.connect()
            conns.append(c)
        sizes = [65536 + i * 4099 for i in range(len(conns))]
        for c, n in zip(conns, sizes):
            c.request("GET", f"/n/{n}")
        for c, n in zip(conns, sizes):
            resp = c.getresponse()
            assert resp.status == 200
            assert resp.read() == expected_body(n), n
    finally:
        for c in conns:
            c.close()


def test_response_too_large_to_segment(sized_tls_server):
    """Past the per-response block cap the write path takes one allocation for
    the whole response instead of draining the shared pool into a single
    writev.  The connection has to survive both that and the switch back."""
    _proto, port = sized_tls_server
    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=60
    )
    try:
        for n in (2_500_000, 1000, 3_000_000, 65536):
            conn.request("GET", f"/n/{n}")
            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.read() == expected_body(n), n
    finally:
        conn.close()


def _stats(conn):
    """Read the server's encryption-block counters over the connection.

    Sampled from inside the app callback, so the response being asked about has
    not been encrypted yet: on a quiescent connection every block the previous
    responses used has already gone back, because on_write fires before the
    client can finish reading the body it was carrying.
    """
    conn.request("GET", "/stats")
    resp = conn.getresponse()
    assert resp.status == 200
    return json.loads(resp.read())


def test_every_block_of_a_segmented_response_comes_back(sized_tls_server):
    """Nothing is still held after responses spanning one, several and more
    than TLS_WSEG_MAX blocks.

    A block released twice would have crashed by now; one never released shows
    up here and nowhere else, since a leak costs only memory and the suite is
    far too short to notice that.
    """
    _proto, port = sized_tls_server
    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=30
    )
    try:
        before = _stats(conn)
        assert before["blocks_live"] == 0, before
        assert before["bigbufs_live"] == 0, before

        for n in [500, 65536, 0, 262144, 16897, 2_500_000, 12000]:
            conn.request("GET", f"/n/{n}")
            resp = conn.getresponse()
            assert resp.read() == expected_body(n), n

        after = _stats(conn)
        assert after["blocks_live"] == 0, after
        assert after["bigbufs_live"] == 0, after
    finally:
        conn.close()


def test_segmented_responses_stop_allocating(sized_tls_server):
    """The steady-state write path allocates nothing, at any body size.

    Before segmentation every response over the cliff did malloc(need) and, on
    release, a ptls_clear_memory() over the whole ciphertext.  A 64KB response
    is now four pooled blocks, so once the pool has reached its high-water mark
    a run of them must not allocate at all.
    """
    _proto, port = sized_tls_server
    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=30
    )
    try:
        # Warm up: the pool has to grow to this response's block count once.
        for _ in range(3):
            conn.request("GET", "/n/65536")
            assert len(conn.getresponse().read()) == 65536

        base = _stats(conn)["mallocs"]
        for _ in range(25):
            conn.request("GET", "/n/65536")
            assert len(conn.getresponse().read()) == 65536
        assert _stats(conn)["mallocs"] == base

        # Past TLS_WSEG_MAX the response takes a single oversized buffer.  The
        # retained slot is deliberately capped, so one this large is freed on
        # release rather than pinning that much per worker: these do allocate,
        # once each, by design.
        for _ in range(2):
            conn.request("GET", "/n/3000000")
            assert len(conn.getresponse().read()) == 3_000_000
        assert _stats(conn)["mallocs"] >= base + 2
    finally:
        conn.close()


def test_blocks_released_when_a_large_response_is_abandoned(sized_tls_server):
    """Close paths that never reach on_write still give every block back.

    Dropping the connection while a segmented response is in flight leaves the
    chain reachable only from tls_conn_free(), which is the safety net every
    uv_close() funnels through.
    """
    _proto, port = sized_tls_server
    for _ in range(12):
        raw = socket.create_connection(("127.0.0.1", port), timeout=20)
        s = tls_context().wrap_socket(raw, server_hostname="localhost")
        s.sendall(b"GET /n/262144 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        s.recv(64)  # let the response start, then walk away mid-write
        s.close()

    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=20
    )
    try:
        conn.request("GET", "/n/65536")
        assert len(conn.getresponse().read()) == 65536
        st = _stats(conn)
        assert st["blocks_live"] == 0, st
        assert st["bigbufs_live"] == 0, st
    finally:
        conn.close()


def test_bad_request_over_tls_releases_cleanly(sized_tls_server):
    """The 400 path closes without going through on_write, so tls_conn_free()
    is the only release the connection gets.  Preceding it with a segmented
    response means that release runs on a client that held a chain earlier in
    its life."""
    _proto, port = sized_tls_server
    for _ in range(3):
        raw = socket.create_connection(("127.0.0.1", port), timeout=20)
        s = tls_context().wrap_socket(raw, server_hostname="localhost")
        try:
            s.sendall(b"GET /n/65536 HTTP/1.1\r\nHost: localhost\r\n\r\n")
            body, _rest = _read_one_response(s, b"")
            assert body == expected_body(65536)
            # No request line at all: phr_parse_request fails, the server
            # answers 400 and closes.
            s.sendall(b"\x01\x02 not a request \r\n\r\n")
            with contextlib.suppress(OSError, ssl.SSLError):
                s.recv(4096)
        finally:
            s.close()

    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=20
    )
    try:
        st = _stats(conn)
        assert st["blocks_live"] == 0, st
        assert st["bigbufs_live"] == 0, st
    finally:
        conn.close()


def test_handshake_failure_releases_cleanly(sized_tls_server):
    """A connection that never completes a handshake still reaches
    tls_conn_free(), with no encryption block ever taken."""
    _proto, port = sized_tls_server
    junk = [
        b"\x16\x03\x01\x00\x05hello",  # TLS record header, garbage body
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",  # plaintext HTTP to a TLS port
        b"\x00" * 64,
    ]
    for payload in junk:
        # Short timeout: some of these draw an alert and some just sit there,
        # and the point is only that the server tore the connection down.
        with (
            socket.create_connection(("127.0.0.1", port), timeout=0.5) as raw,
            contextlib.suppress(OSError),
        ):
            raw.sendall(payload)
            raw.recv(4096)

    # A well-formed client the server must still reject: it caps at TLS 1.2
    # and the server is 1.3-only, so the handshake fails partway through.
    ctx = tls_context()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    for _ in range(3):
        with (
            socket.create_connection(("127.0.0.1", port), timeout=10) as raw,
            pytest.raises((ssl.SSLError, OSError)),
            ctx.wrap_socket(raw, server_hostname="localhost") as s,
        ):
            s.do_handshake()

    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=20
    )
    try:
        st = _stats(conn)
        assert st["blocks_live"] == 0, st
        assert st["bigbufs_live"] == 0, st
    finally:
        conn.close()


def test_read_failure_while_a_segmented_response_is_writing(sized_tls_server):
    """A decryption failure discovered while a multi-block response is on the
    wire: the interaction between the deferred read teardown and the chain.

    Reading stays armed across a response, so tls_read_failed() can fire while
    uv_write still holds every block of a segmented response.  It must not
    close there -- on_write would then close a second time, which libuv aborts
    on -- so it defers, and on_write releases the chain and closes.  Nothing in
    either change alone exercises that: before segmentation there was one
    buffer rather than a chain, and before the read stayed armed this could not
    happen at all.

    Whether any one iteration wins the race depends on the response still being
    on the wire when the bad record lands; instrumenting tls_read_failed()
    while writing this showed 9 of 10 taking the deferred branch with blocks
    held.  The counters are checked afterwards either way.
    """
    _proto, port = sized_tls_server
    # 2000000 is a block chain; 3000000 is past TLS_WSEG_MAX, so it holds the
    # oversized buffer instead.  Both have to survive the deferred teardown.
    for n in [2_000_000, 3_000_000] * 3:
        with socket.create_connection(("127.0.0.1", port), timeout=20) as raw:
            sock, _incoming, outgoing = _handshake_over_bio(raw, tls_context())
            sock.write(f"GET /n/{n} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
            raw.sendall(outgoing.read())
            # A well-formed application-data record whose body cannot possibly
            # authenticate: ptls_receive() fails while the response is still
            # being written.
            raw.sendall(b"\x17\x03\x03\x00\x20" + os.urandom(32))
            with contextlib.suppress(OSError, ssl.SSLError):
                while raw.recv(65536):
                    pass

    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=20
    )
    try:
        conn.request("GET", "/n/65536")
        assert len(conn.getresponse().read()) == 65536
        st = _stats(conn)
        assert st["blocks_live"] == 0, st
        assert st["bigbufs_live"] == 0, st
    finally:
        conn.close()


# TLS_WSEG_MAX in freastal/src/server.h: blocks one response may claim before
# it takes a single oversized buffer instead.
WSEG_MAX = 128


def _response_records(port, size):
    """Ask for /n/<size> over memory BIOs; return (body, records).

    A wrapped socket hides the record framing entirely.  Driving the TLS
    session through memory BIOs keeps every raw byte, and a record's type and
    length are in the clear, so the framing the server chose can be read off
    without decrypting anything.

    One connection per call: the capture then holds exactly this response's
    records, with no earlier response's tail in front of it.
    """
    with socket.create_connection(("127.0.0.1", port), timeout=20) as raw:
        sock, incoming, outgoing = _handshake_over_bio(raw, tls_context())
        sock.write(f"GET /n/{size} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        raw.sendall(outgoing.read())
        raw.settimeout(20)
        reader = _BioReader(raw, sock, incoming)
        body, rest = _read_one_response(reader, b"")
    assert rest == b""
    records = _tls_records(bytes(reader.ciphertext))
    assert all(t == CONTENT_TYPE_APPDATA for t, _ in records), records
    return body, records


def _plaintext_len(records):
    """Plaintext the server fed picotls, recovered from the record lengths.

    Each record's length field covers the payload, the content-type byte and
    the AEAD tag, so subtracting the inner overhead per record gives back the
    response header plus the body.  Deriving it beats hardcoding the header
    length, which moves whenever the response header does.
    """
    return sum(ln - RECORD_INNER_OVERHEAD for _t, ln in records)


# Sizes chosen against the framing, not against a buffer: 8193 and 16000 were
# two records before header and body shared one, 16383-16385 bracket the record
# limit itself, and everything above needs the stream split.
# fmt: off

def test_response_at_the_segmentation_cap(sized_tls_server):
    """The exact body size where the pooled chain reaches TLS_WSEG_MAX blocks.

    This is where the per-record accounting is least forgiving, and it moved
    with this change: nrec is counted over the header and the body together,
    because that is how ptls_send_v() cuts records.  Counting the header's
    records separately and adding predicts one too many here, which quietly
    sends a response that fits in exactly TLS_WSEG_MAX blocks down the
    oversized path -- right bytes, wrong path, so only the block counters
    notice.  Under-counting is the dangerous direction: it would run the chain
    past the end of uvbufs[TLS_WSEG_MAX].

    Every record here is maximal, so one block holds one record and the chain
    is exactly as long as the record count.
    """
    _proto, port = sized_tls_server
    cap = WSEG_MAX * MAX_RECORD_PLAINTEXT

    # Learn this app's response-header length at a body with the same number of
    # Content-Length digits, so the sizes below land on the boundary instead of
    # near it.
    probe = cap - 200
    _body, records = _response_records(port, probe)
    hdr_len = _plaintext_len(records) - probe
    assert len(records) == WSEG_MAX, (hdr_len, len(records))

    conn = http.client.HTTPSConnection(
        "127.0.0.1", port, context=tls_context(), timeout=60
    )
    try:
        # Either side of the cap, then a small one to prove the switch back.
        for n in (cap - hdr_len - 1, cap - hdr_len, cap - hdr_len + 1, 1000):
            conn.request("GET", f"/n/{n}")
            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.read() == expected_body(n), n

        after = _stats(conn)
        assert after["blocks_live"] == 0, after
        assert after["bigbufs_live"] == 0, after
        # A chain of exactly TLS_WSEG_MAX blocks was built and returned: had
        # the count come out one high, the response at the cap would have taken
        # one oversized buffer and the pool would never have grown this far.
        assert after["pool_free"] >= WSEG_MAX, after
    finally:
        conn.close()
