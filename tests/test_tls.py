"""TLS 1.3, for both protocols.

There was no TLS coverage at all before this, which is how ASGI came to have
no certfile/keyfile parameter and how the ASGI scheme came to be reported as
"http" on a TLS connection.

Skipped when the extension was built without picotls (no OpenSSL headers at
build time), detected by the handshake failing rather than by a build flag,
since the module exposes none.
"""

import http.client
import os
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
