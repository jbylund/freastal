"""Request header *name* handling.

Header names are served out of a pre-built cache keyed on the lowercased name.
A cached entry is only usable after a full byte compare, so these tests push on
the cases where a length-or-prefix match must not be mistaken for a hit, and on
the names that never come from the cache at all.
"""

import socket
from urllib.parse import urlparse

import pytest


def _raw(server_url, headers, path="/headers", extra=b""):
    """Send a request with exactly these header lines and return the body."""
    parsed = urlparse(server_url)
    req = f"GET {path} HTTP/1.1\r\n".encode()
    for name, value in headers:
        req += f"{name}: {value}\r\n".encode("latin-1")
    req += extra
    req += b"\r\n"

    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.sendall(req)
        sock.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        while len(body) < length:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
    return head, body


def _pairs(server_url, headers):
    head, body = _raw(server_url, headers)
    assert head.startswith(b"HTTP/1.1 200"), head
    return dict(
        line.split("=", 1) for line in body.decode("latin-1").split("\n") if line
    )


def test_cached_names_are_lowercased_whatever_the_wire_case(server_url):
    seen = _pairs(
        server_url,
        [
            ("HOST", "example.test"),
            ("User-AGENT", "probe/1"),
            ("ACCEPT-ENCODING", "gzip"),
            ("Connection", "keep-alive"),
        ],
    )
    assert seen["host"] == "example.test"
    assert seen["user-agent"] == "probe/1"
    assert seen["accept-encoding"] == "gzip"
    assert seen["connection"] == "keep-alive"


@pytest.mark.parametrize(
    "name",
    [
        "hosx",           # same length and prefix as "host"
        "xost",           # same length as "host", different first byte
        "user-agenz",     # same length as "user-agent"
        "connectiom",     # same length as "connection"
        "hosts",          # a cached name plus a byte
        "hos",            # a cached name minus a byte
    ],
)
def test_near_miss_names_do_not_borrow_a_cached_object(server_url, name):
    """A client picks its own header names, so a partial match must not hit."""
    seen = _pairs(server_url, [("Host", "x"), (name, "sentinel")])
    assert seen[name.lower()] == "sentinel"
    assert seen["host"] == "x"


def test_underscore_name_is_not_confused_with_the_dashed_cached_one(asgi_url):
    """ASGI keeps the wire name, so "x_real_ip" must not come back as the
    cached b"x-real-ip".  (WSGI folds both onto HTTP_X_REAL_IP by design.)"""
    seen = _pairs(asgi_url, [("Host", "x"), ("x_real_ip", "sentinel")])
    assert seen["x_real_ip"] == "sentinel"
    assert "x-real-ip" not in seen


def test_uncached_name_is_built_correctly(server_url):
    seen = _pairs(server_url, [("Host", "x"), ("X-Custom-Thing", "yes")])
    assert seen["x-custom-thing"] == "yes"


def test_very_long_header_name_survives(server_url):
    """Names longer than the old 256-byte key buffer used to be truncated
    (ASGI) or dropped entirely (WSGI); they are now built at full length."""
    name = "x-" + "a" * 300
    seen = _pairs(server_url, [("Host", "x"), (name, "long")])
    assert seen[name] == "long"


def test_obs_fold_continuation_line_does_not_crash(server_url):
    """picohttpparser reports a folded line as name=NULL/name_len=0; the
    lookup must reject it on the length alone, without reading the pointer."""
    head, _ = _raw(
        server_url,
        [("Host", "x"), ("X-Fold", "first")],
        extra=b" continued\r\n",
    )
    assert head.startswith(b"HTTP/1.1 200"), head
