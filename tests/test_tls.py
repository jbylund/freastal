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


@pytest.fixture(scope="module")
def certpair():
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available to mint a test certificate")
    d = tempfile.mkdtemp()
    cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    subprocess.run(
        [
            "openssl",
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
    proc.kill()
    pytest.skip(f"{proto} over TLS never became reachable; build likely lacks picotls")


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
    proc.kill()
    pytest.skip(f"{proto} sized server never became reachable")


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


def _read_one_response(sock, buf):
    """Pull one complete HTTP/1.1 response out of sock, returning (body, rest)."""
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
    return rest[:length], rest[length:]


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
    if shutil.which("openssl") is None:
        pytest.skip("openssl s_client not available")
    proc = subprocess.run(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{port}", *args],
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


# TLS 1.3 caps a record's plaintext at 16KB and frames it with 22 bytes: a
# 5-byte header outside the length field, then the content-type byte and the
# 16-byte AEAD tag inside it.
MAX_RECORD_PLAINTEXT = 16384
RECORD_INNER_OVERHEAD = 17
CONTENT_TYPE_APPDATA = 23


@pytest.mark.parametrize("size", [65536, 100000])
def test_multi_block_response_keeps_maximal_record_framing(sized_tls_server, size):
    """A response spanning several encryption blocks, seen on the wire.

    Above one block the response is encrypted a record at a time into a chain
    of pooled blocks and sent as one writev.  What must not change is the
    framing: one record for the response header, then the body in maximal
    16KB records.  Splitting the body anywhere else -- at a block boundary,
    say, or once per iovec -- still decrypts to the right bytes, so a test
    that only checks the body cannot tell the difference.  This one can.
    """
    _proto, port = sized_tls_server
    with socket.create_connection(("127.0.0.1", port), timeout=20) as raw:
        sock, incoming, outgoing = _handshake_over_bio(raw, tls_context())
        sock.write(f"GET /n/{size} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        raw.sendall(outgoing.read())
        raw.settimeout(20)
        reader = _BioReader(raw, sock, incoming)
        body, rest = _read_one_response(reader, b"")

    assert body == expected_body(size)
    assert rest == b""

    records = _tls_records(bytes(reader.ciphertext))
    assert all(t == CONTENT_TYPE_APPDATA for t, _ in records), records

    chunks = [
        min(MAX_RECORD_PLAINTEXT, size - o)
        for o in range(0, size, MAX_RECORD_PLAINTEXT)
    ]
    want = [n + RECORD_INNER_OVERHEAD for n in chunks]
    assert [ln for _t, ln in records[1:]] == want
    # The header rides in its own record in front of the first body record,
    # not in a block of its own.
    assert records[0][1] < 1024, records[0]


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
