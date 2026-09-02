"""A request body that arrives in a later read() than its headers.

Any client that writes the header block and the body as separate segments
produces this - curl with a large body, an Expect: 100-continue flow, a slow
or throttled uploader - so it is not an exotic case.
"""

import socket
import subprocess
import sys
import time

import pytest

APP = r"""
import freastal

def app(environ, start_response):
    body = environ["wsgi.input"].read()
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"got:" + body]

freastal.serve(app, host="127.0.0.1", port=PORT, workers=1, reuse_port=False)
"""


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def port():
    p = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-c", f"PORT = {p}\n" + APP],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=0.25) as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                if s.recv(64):
                    break
        except OSError:
            time.sleep(0.05)
    else:
        proc.kill()
        pytest.fail("server did not start")
    yield p
    proc.kill()
    proc.wait(timeout=10)


def _split_post(port, head_part, tail_part, total_len, gap=0.02):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: "
            + str(total_len).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + head_part
        )
        time.sleep(gap)  # force a second read() on the server
        if tail_part:
            s.sendall(tail_part)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf


@pytest.mark.parametrize(
    "head,tail",
    [
        (b"ab", b"cdefgh"),  # body split mid-way
        (b"", b"abcdefgh"),  # no body bytes in the first segment at all
        (b"abcdefg", b"h"),  # one byte arrives late
    ],
)
def test_body_arriving_after_the_headers_is_answered(port, head, tail):
    raw = _split_post(port, head, tail, 8)
    assert raw, "server never responded (regression: the request hangs)"
    assert raw.startswith(b"HTTP/1.1 200"), raw[:60]
    assert raw.endswith(b"got:abcdefgh"), raw[-40:]


def test_server_still_healthy_after_a_split_body(port):
    _split_post(port, b"ab", b"cdefgh", 8)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        assert s.recv(4096).startswith(b"HTTP/1.1 200")


def test_body_in_one_segment_still_works(port):
    """Guard against fixing the split case by breaking the common one."""
    raw = _split_post(port, b"abcdefgh", b"", 8, gap=0)
    assert raw.startswith(b"HTTP/1.1 200"), raw[:60]
    assert raw.endswith(b"got:abcdefgh")
