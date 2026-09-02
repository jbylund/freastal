"""Tests that run against both WSGI and ASGI via the server_url fixture."""

import socket
from urllib.parse import urlparse

import httpx


def test_hello(server_url):
    r = httpx.get(f"{server_url}/hello")
    assert r.status_code == 200
    assert r.text == "hello"


def test_404(server_url):
    r = httpx.get(f"{server_url}/notexist")
    assert r.status_code == 404


def test_post_echo(server_url):
    r = httpx.post(f"{server_url}/echo", content=b"payload")
    assert r.status_code == 200
    assert r.content == b"payload"


def test_request_header_visible(server_url):
    r = httpx.get(f"{server_url}/header", headers={"X-Test": "freastal"})
    assert r.status_code == 200
    assert r.text == "freastal"


def test_query_string(server_url):
    r = httpx.get(f"{server_url}/query?foo=bar&baz=1")
    assert r.status_code == 200
    assert r.text == "foo=bar&baz=1"


def test_remote_addr(server_url):
    r = httpx.get(f"{server_url}/remote-addr")
    assert r.status_code == 200
    assert r.text == "127.0.0.1"


def test_content_length_auto(server_url):
    r = httpx.get(f"{server_url}/hello")
    assert "content-length" in r.headers
    assert int(r.headers["content-length"]) == len(b"hello")


def test_keep_alive(server_url):
    with httpx.Client() as client:
        for _ in range(10):
            r = client.get(f"{server_url}/hello")
            assert r.status_code == 200
            assert r.text == "hello"


def _read_until(sock, needle, count, timeout=2.0):
    """Read from sock until `needle` has been seen `count` times, or we stall."""
    sock.settimeout(timeout)
    data = b""
    try:
        while data.count(needle) < count:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def test_pipelined_requests(server_url):
    """Requests arriving in one segment must all be answered, not just the first.

    Before this was fixed the bytes of every request after the first were
    dropped by client_reset(), so a pipelining client hung waiting forever.
    """
    parsed = urlparse(server_url)
    n = 3
    req = b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n" * n

    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.sendall(req)
        data = _read_until(sock, b"HTTP/1.1 200", n)

    assert data.count(b"HTTP/1.1 200") == n
    assert data.count(b"hello") == n


def test_pipelined_requests_with_bodies(server_url):
    """Pipelining must account for request bodies when finding the next request."""
    parsed = urlparse(server_url)
    req = (
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nfirst"
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\n\r\nsecond"
    )

    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.sendall(req)
        data = _read_until(sock, b"HTTP/1.1 200", 2)

    assert data.count(b"HTTP/1.1 200") == 2
    assert b"first" in data
    assert b"second" in data
