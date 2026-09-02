"""Application and response-iterable shapes.

collect_body() takes a [b"..."] apart directly and only falls back to the
iterator protocol for anything else, so each shape that must keep working
needs a case here - in particular the subclasses, which have to take the slow
path because their __iter__ or tp_as_sequence can do anything.  The app itself
is called through PyObject_Vectorcall, which reaches a different code path in
CPython for a plain function than for a callable instance or a bound method.
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


APP = r"""
import functools, sys
import freastal


def _respond(start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])


class ListSub(list):
    pass


class BytesSub(bytes):
    pass


def by_path(environ, start_response):
    p = environ["PATH_INFO"]
    _respond(start_response)
    if p == "/list":
        return [b"body"]
    if p == "/list-sub":
        return ListSub([b"body"])
    if p == "/bytes-sub":
        return [BytesSub(b"body")]
    if p == "/tuple":
        return (b"bo", b"dy")
    if p == "/empty":
        return []
    if p == "/chunks":
        return [b"bo", b"", b"dy"]
    if p == "/generator":
        return (c for c in (b"bo", b"dy"))
    if p == "/not-bytes":
        return ["body"]
    return [b"body"]


class Instance:
    def __call__(self, environ, start_response):
        return by_path(environ, start_response)


class Methods:
    def bound(self, environ, start_response):
        return by_path(environ, start_response)


APPS = {
    "function": by_path,
    "instance": Instance(),
    "bound-method": Methods().bound,
    "partial": functools.partial(lambda e, s: by_path(e, s)),
}
freastal.serve(APPS[KIND], host="127.0.0.1", port=PORT, workers=1, reuse_port=False)
"""


def _spawn(port, kind):
    proc = subprocess.Popen(
        [sys.executable, "-c", f"PORT = {port}\nKIND = {kind!r}\n" + APP],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25) as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                if s.recv(64):
                    return proc
        except OSError:
            time.sleep(0.05)
    proc.kill()
    raise RuntimeError("server did not start")


def _get(port, path):
    """Whole raw response; retries connect because the box runs out of
    ephemeral ports under the other test servers."""
    last = None
    for _ in range(100):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            break
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    else:
        raise last
    with s:
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


@pytest.fixture(
    scope="module", params=["function", "instance", "bound-method", "partial"]
)
def app_port(request):
    port = free_port()
    proc = _spawn(port, request.param)
    yield port
    proc.kill()
    proc.wait(timeout=10)


@pytest.mark.parametrize(
    "path,body",
    [
        ("/list", b"body"),
        ("/list-sub", b"body"),
        ("/bytes-sub", b"body"),
        ("/tuple", b"body"),
        ("/chunks", b"body"),
        ("/generator", b"body"),
        ("/empty", b""),
    ],
)
def test_response_iterable_shapes(app_port, path, body):
    raw = _get(app_port, path)
    assert raw.startswith(b"HTTP/1.1 200"), raw[:60]
    head, _, got = raw.partition(b"\r\n\r\n")
    assert b"Content-Length: %d" % len(body) in head, head
    assert got == body


def test_non_bytes_chunk_is_a_500_not_a_crash(app_port):
    raw = _get(app_port, "/not-bytes")
    assert raw.startswith(b"HTTP/1.1 500"), raw[:60]
    # The worker must still be alive.
    assert _get(app_port, "/list").startswith(b"HTTP/1.1 200")
