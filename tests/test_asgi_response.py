"""Byte-level tests for the ASGI response header block.

These drive a dedicated server over a raw socket rather than httpx, so the
status line, the auto Content-Length and the header lines can be asserted
exactly as they go on the wire.
"""

import multiprocessing
import socket

import pytest

import freastal
from conftest import _free_port, _wait_for_port

# The reason phrases freastal emits, mirroring status_line() in asgi.c.
REASONS = {
    100: "Continue",
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    206: "Partial Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    410: "Gone",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


class _Pair:
    """A two-element sequence that is neither a list nor a tuple."""

    def __init__(self, name, value):
        self._items = (name, value)

    def __getitem__(self, i):
        return self._items[i]


def _query(scope):
    qs = scope.get("query_string", b"").decode()
    return dict(p.split("=", 1) for p in qs.split("&") if p)


async def _app(scope, receive, send):
    path = scope.get("path", "/")
    q = _query(scope)
    status, headers, body = 200, [[b"content-type", b"text/plain"]], b""

    if path == "/status":
        status = int(q["code"])
    elif path == "/len":
        body = b"x" * int(q["n"])
    elif path == "/tuple-headers":
        headers = [(b"content-type", b"text/plain"), (b"x-tuple", b"1")]
    elif path == "/weird-headers":
        headers = [_Pair(b"content-type", b"text/plain"), _Pair(b"x-weird", b"1")]
    elif path == "/long-pair":
        headers = [[b"content-type", b"text/plain", b"ignored"]]
    elif path == "/app-supplied":
        body = b"hello"
        headers = [
            [b"content-type", b"text/plain"],
            [b"Content-Length", b"5"],
            [b"Connection", b"close"],
        ]
    elif path == "/bad-header":
        headers = [["content-type", "text/plain"]]  # str, not bytes
    elif path == "/overflow":
        headers = [[b"x-big", b"v" * 9000]]

    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _serve(port):
    freastal.serve_asgi(_app, host="127.0.0.1", port=port, workers=1, reuse_port=False)


@pytest.fixture(scope="module")
def raw_url():
    port = _free_port()
    p = multiprocessing.Process(target=_serve, args=(port,), daemon=True)
    p.start()
    _wait_for_port("127.0.0.1", port)
    yield ("127.0.0.1", port)
    p.terminate()
    p.join(timeout=3)


def _fetch(addr, target):
    """One request on a fresh connection; returns the whole raw response."""
    with socket.create_connection(addr, timeout=5) as s:
        s.sendall(
            f"GET {target} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".encode()
        )
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks)


def _split(resp):
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    return lines[0], lines[1:], body


def test_every_table_status_line_is_exact(raw_url):
    for code, reason in REASONS.items():
        line, _, _ = _split(_fetch(raw_url, f"/status?code={code}"))
        assert line == f"HTTP/1.1 {code} {reason}".encode(), code


@pytest.mark.parametrize("code", [203, 418, 599])
def test_status_outside_the_table_falls_back_to_unknown(raw_url, code):
    line, _, _ = _split(_fetch(raw_url, f"/status?code={code}"))
    assert line == f"HTTP/1.1 {code} Unknown".encode()


@pytest.mark.parametrize("n", [0, 1, 9, 10, 99, 100, 999, 1000, 4095, 65536])
def test_auto_content_length_digits(raw_url, n):
    line, hdrs, body = _split(_fetch(raw_url, f"/len?n={n}"))
    assert line == b"HTTP/1.1 200 OK"
    assert f"Content-Length: {n}".encode() in hdrs
    assert len(body) == n


def test_tuple_header_pairs(raw_url):
    _, hdrs, _ = _split(_fetch(raw_url, "/tuple-headers"))
    assert b"content-type: text/plain" in hdrs
    assert b"x-tuple: 1" in hdrs


def test_non_list_non_tuple_pairs_still_work(raw_url):
    """The PySequence_GetItem fallback, for pairs that are neither list nor tuple."""
    _, hdrs, _ = _split(_fetch(raw_url, "/weird-headers"))
    assert b"content-type: text/plain" in hdrs
    assert b"x-weird: 1" in hdrs


def test_pairs_longer_than_two_use_the_first_two_items(raw_url):
    _, hdrs, _ = _split(_fetch(raw_url, "/long-pair"))
    assert b"content-type: text/plain" in hdrs
    assert not any(h.startswith(b"ignored") for h in hdrs)


def test_app_supplied_content_length_and_connection_are_not_duplicated(raw_url):
    _, hdrs, body = _split(_fetch(raw_url, "/app-supplied"))
    assert body == b"hello"
    assert sum(h.lower().startswith(b"content-length:") for h in hdrs) == 1
    assert sum(h.lower().startswith(b"connection:") for h in hdrs) == 1


def test_non_bytes_header_is_rejected(raw_url):
    line, _, _ = _split(_fetch(raw_url, "/bad-header"))
    assert line == b"HTTP/1.1 500 Internal Server Error"


def test_header_block_overflow_is_rejected_not_truncated(raw_url):
    """A block larger than RESP_HDR_SIZE must fail cleanly, not overrun."""
    line, hdrs, _ = _split(_fetch(raw_url, "/overflow"))
    assert line == b"HTTP/1.1 500 Internal Server Error"
    assert not any(h.startswith(b"x-big:") for h in hdrs)
