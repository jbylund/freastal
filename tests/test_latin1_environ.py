"""PEP 3333 requires environ str values to be decoded as ISO-8859-1.

They were decoded as UTF-8, so any byte above 0x7F in the path, the query
string or a header value failed to decode. The failure left an exception set
rather than being handled, and the whole request came back as a 500 -- which
any client could trigger with a single byte.
"""

import socket
from urllib.parse import urlparse

import pytest


def _raw(server_url, request_bytes, read_timeout=5.0):
    """Send raw bytes so we can put non-UTF-8 on the wire, which no HTTP
    client library will do for us."""
    parsed = urlparse(server_url)
    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.sendall(request_bytes)
        sock.settimeout(read_timeout)
        data = b""
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except TimeoutError:
            pass
    status, _, rest = data.partition(b"\r\n")
    _, _, body = rest.partition(b"\r\n\r\n")
    return status, body


def test_non_utf8_header_value_is_served(wsgi_url):
    status, body = _raw(
        wsgi_url,
        b"GET /echo-header HTTP/1.1\r\nHost: x\r\nX-Test: caf\xe9 na\xefve\r\n"
        b"Connection: close\r\n\r\n",
    )
    assert status == b"HTTP/1.1 200 OK", status
    assert body == "café naïve".encode("latin-1")


def test_non_utf8_path_is_served(wsgi_url):
    status, body = _raw(
        wsgi_url,
        b"GET /echo-path/caf\xe9 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    assert status == b"HTTP/1.1 200 OK", status
    assert body == b"/echo-path/caf\xe9"


def test_non_utf8_query_string_is_served(wsgi_url):
    status, body = _raw(
        wsgi_url,
        b"GET /echo-query?q=caf\xe9 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    assert status == b"HTTP/1.1 200 OK", status
    assert body == b"q=caf\xe9"


def test_non_utf8_content_type_is_served(wsgi_url):
    status, body = _raw(
        wsgi_url,
        b"POST /echo-ctype HTTP/1.1\r\nHost: x\r\nContent-Type: text/caf\xe9\r\n"
        b"Content-Length: 0\r\nConnection: close\r\n\r\n",
    )
    assert status == b"HTTP/1.1 200 OK", status
    assert body == b"text/caf\xe9"


@pytest.mark.parametrize("byte", [0x80, 0xA0, 0xC3, 0xE9, 0xFE, 0xFF])
def test_every_high_byte_round_trips_in_a_header(wsgi_url, byte):
    status, body = _raw(
        wsgi_url,
        b"GET /echo-header HTTP/1.1\r\nHost: x\r\nX-Test: a"
        + bytes([byte])
        + b"z\r\nConnection: close\r\n\r\n",
    )
    assert status == b"HTTP/1.1 200 OK", status
    assert body == b"a" + bytes([byte]) + b"z"


def test_high_byte_in_header_name_is_still_rejected(wsgi_url):
    """Header names are RFC 7230 tokens; picohttpparser rejects bytes >= 0x80
    before environ is built, so this must stay a 400 and not become a header."""
    status, _ = _raw(
        wsgi_url,
        b"GET /hello HTTP/1.1\r\nHost: x\r\nX-caf\xe9: v\r\nConnection: close\r\n\r\n",
    )
    assert status == b"HTTP/1.1 400 Bad Request", status


def test_ascii_values_unchanged(wsgi_url):
    """Regression guard: latin-1 and UTF-8 agree on ASCII, so nothing moves."""
    status, body = _raw(
        wsgi_url,
        b"GET /echo-header?x=1 HTTP/1.1\r\nHost: x\r\nX-Test: plain-ascii\r\n"
        b"Connection: close\r\n\r\n",
    )
    assert status == b"HTTP/1.1 200 OK", status
    assert body == b"plain-ascii"
