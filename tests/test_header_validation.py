"""Response headers supplied by the application must not be able to inject
headers, split the response, or crash the worker.

Each test drives a raw socket rather than an HTTP client, because a client
would normalise away exactly the malformed output being checked for.
"""

import socket
import subprocess
import sys
import time

import pytest


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


WSGI_APP = r"""
import freastal

BAD = {
    "/value-crlf":  [("X-Foo", "a\r\nX-Injected: yes")],
    "/name-crlf":   [("X-Foo\r\nX-Injected: yes", "a")],
    "/value-lf":    [("X-Foo", "a\nX-Injected: yes")],
    "/value-nul":   [("X-Foo", "a\x00b")],
    "/name-space":  [("X Foo", "a")],
    "/name-colon":  [("X:Foo", "a")],
    "/name-empty":  [("", "a")],
    "/value-ctl":   [("X-Foo", "a\x01b")],
}

def app(environ, start_response):
    p = environ["PATH_INFO"]
    if p == "/ok":
        start_response("200 OK", [("Content-Type", "text/plain")])
    elif p == "/list-pair":
        # PEP 3333 asks for tuples; apps pass lists, and that used to be
        # undefined behaviour in the formatter rather than an error.
        start_response("200 OK", [["Content-Type", "text/plain"]])
    elif p == "/status-crlf":
        start_response("200 OK\r\nX-Injected: yes", [("Content-Type", "text/plain")])
    elif p == "/status-short":
        start_response("20", [("Content-Type", "text/plain")])
    elif p == "/tab-ok":
        # HTAB is legal inside a field value and must not be rejected.
        start_response("200 OK", [("X-Foo", "a\tb")])
    elif p == "/latin1-ok":
        # obs-text: PEP 3333 passes values through as latin-1.
        start_response("200 OK", [("X-Foo", "caf\xe9")])
    elif p in BAD:
        start_response("200 OK", BAD[p])
    else:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"ok"]

freastal.serve(app, host="127.0.0.1", port=PORT, workers=1, reuse_port=False)
"""

ASGI_APP = r"""
import freastal

BAD = {
    "/value-crlf": [[b"x-foo", b"a\r\nX-Injected: yes"]],
    "/name-crlf":  [[b"x-foo\r\nX-Injected: yes", b"a"]],
    "/value-lf":   [[b"x-foo", b"a\nX-Injected: yes"]],
    "/value-nul":  [[b"x-foo", b"a\x00b"]],
    "/name-space": [[b"x foo", b"a"]],
    "/name-empty": [[b"", b"a"]],
    "/value-ctl":  [[b"x-foo", b"a\x01b"]],
}

async def app(scope, receive, send):
    p = scope["path"]
    if p == "/ok":
        h = [[b"content-type", b"text/plain"]]
    elif p == "/tuple-pair":
        h = [(b"content-type", b"text/plain")]
    elif p == "/tab-ok":
        h = [[b"x-foo", b"a\tb"]]
    elif p == "/latin1-ok":
        h = [[b"x-foo", b"caf\xe9"]]
    elif p in BAD:
        h = BAD[p]
    else:
        h = [[b"content-type", b"text/plain"]]
    await send({"type": "http.response.start", "status": 200, "headers": h})
    await send({"type": "http.response.body", "body": b"ok"})

freastal.serve_asgi(app, host="127.0.0.1", port=PORT, workers=1, reuse_port=False)
"""


def _spawn(src, port):
    proc = subprocess.Popen(
        [sys.executable, "-c", f"PORT = {port}\n" + src],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25) as s:
                s.sendall(b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n")
                if s.recv(64):
                    return proc
        except OSError:
            time.sleep(0.05)
    proc.kill()
    raise RuntimeError("server did not start")


def _raw_get(port, path):
    """Return the complete raw response bytes, or b"" if the peer sent nothing."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode()
        )
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf


@pytest.fixture(scope="module")
def wsgi_port():
    port = free_port()
    proc = _spawn(WSGI_APP, port)
    yield port
    proc.kill()
    proc.wait(timeout=10)


@pytest.fixture(scope="module")
def asgi_port():
    port = free_port()
    proc = _spawn(ASGI_APP, port)
    yield port
    proc.kill()
    proc.wait(timeout=10)


REJECTED_WSGI = [
    "/value-crlf", "/name-crlf", "/value-lf", "/value-nul",
    "/name-space", "/name-colon", "/name-empty", "/value-ctl",
    "/status-crlf", "/status-short",
]
REJECTED_ASGI = [
    "/value-crlf", "/name-crlf", "/value-lf", "/value-nul",
    "/name-space", "/name-empty", "/value-ctl",
]


@pytest.mark.parametrize("path", REJECTED_WSGI)
def test_wsgi_rejects_unsafe_headers(wsgi_port, path):
    raw = _raw_get(wsgi_port, path)
    assert raw, f"{path}: server sent nothing (crashed?)"
    assert b"X-Injected" not in raw, f"{path}: header injection succeeded"
    assert raw.startswith(b"HTTP/1.1 500"), f"{path}: expected 500, got {raw[:40]!r}"


@pytest.mark.parametrize("path", REJECTED_ASGI)
def test_asgi_rejects_unsafe_headers(asgi_port, path):
    raw = _raw_get(asgi_port, path)
    assert raw, f"{path}: server sent nothing (crashed?)"
    assert b"X-Injected" not in raw, f"{path}: header injection succeeded"
    assert raw.startswith(b"HTTP/1.1 500"), f"{path}: expected 500, got {raw[:40]!r}"


def test_wsgi_list_header_pair_does_not_crash(wsgi_port):
    """This used to reach PyTuple_GET_ITEM on a list, which is UB."""
    raw = _raw_get(wsgi_port, "/list-pair")
    assert raw.startswith(b"HTTP/1.1 200"), raw[:60]
    assert b"content-type: text/plain" in raw.lower()
    # The worker must still be alive afterwards.
    assert _raw_get(wsgi_port, "/ok").startswith(b"HTTP/1.1 200")


def test_asgi_tuple_header_pair_still_works(asgi_port):
    raw = _raw_get(asgi_port, "/tuple-pair")
    assert raw.startswith(b"HTTP/1.1 200"), raw[:60]


@pytest.mark.parametrize("path", ["/tab-ok", "/latin1-ok"])
def test_wsgi_allows_legal_unusual_values(wsgi_port, path):
    """HTAB and obs-text are legal in a field value; do not over-reject."""
    raw = _raw_get(wsgi_port, path)
    assert raw.startswith(b"HTTP/1.1 200"), f"{path}: {raw[:60]!r}"


@pytest.mark.parametrize("path", ["/tab-ok", "/latin1-ok"])
def test_asgi_allows_legal_unusual_values(asgi_port, path):
    raw = _raw_get(asgi_port, path)
    assert raw.startswith(b"HTTP/1.1 200"), f"{path}: {raw[:60]!r}"


def test_normal_responses_are_unaffected(wsgi_port, asgi_port):
    assert _raw_get(wsgi_port, "/ok").startswith(b"HTTP/1.1 200")
    assert _raw_get(asgi_port, "/ok").startswith(b"HTTP/1.1 200")
