"""The bridge runs loop._ready from C instead of calling loop._run_once().

asgi_drain_ready() has to reproduce _run_once()'s tail exactly: skip cancelled
handles, and survive a callback whose exception escapes Handle._run() without
leaving the rest of the queue stranded.  Neither is reachable through the
shared ASGI fixture, so this module drives a server of its own.
"""

import asyncio
import multiprocessing
import socket

import pytest

import freastal
from conftest import _free_port, _wait_for_port
from freastal._freastal import ASGI_CORO_DONE, asgi_coro_step

_fired = []


async def _app(scope, receive, send):
    path = scope.get("path", "/")
    loop = asyncio.get_running_loop()
    headers = [[b"content-type", b"text/plain"]]
    body = b"ok"

    if path == "/cancelled-handle":
        # A cancelled handle sits on _ready like any other and must not run.
        _fired.clear()
        loop.call_soon(_fired.append, "ran").cancel()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        body = ",".join(_fired).encode() or b"none"
    elif path == "/raising-callback":
        loop.call_soon(_boom)
        await asyncio.sleep(0)
        body = b"survived"
    elif path == "/generator-headers":
        # The spec asks only for an iterable of pairs, so a one-shot iterator
        # has to be materialised before the body event reads it.
        headers = iter([[b"content-type", b"text/plain"], [b"x-gen", b"1"]])
    elif path == "/tuple-header-block":
        headers = ((b"content-type", b"text/plain"), (b"x-tup", b"1"))

    await send({"type": "http.response.start", "status": 200, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _boom():
    raise ValueError("callback blew up")


def _serve(port):
    freastal.serve_asgi(_app, host="127.0.0.1", port=port, workers=1, reuse_port=False)


@pytest.fixture(scope="module")
def addr():
    port = _free_port()
    p = multiprocessing.Process(target=_serve, args=(port,), daemon=True)
    p.start()
    _wait_for_port("127.0.0.1", port)
    yield ("127.0.0.1", port)
    p.terminate()
    p.join(timeout=3)


def _fetch(addr, target):
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


def test_cancelled_handles_are_not_run(addr):
    assert _fetch(addr, "/cancelled-handle").endswith(b"none")


def test_a_callback_that_raises_does_not_wedge_the_loop(addr):
    assert _fetch(addr, "/raising-callback").endswith(b"survived")
    # The queue must still be drained afterwards, on this and later requests.
    assert _fetch(addr, "/cancelled-handle").endswith(b"none")


def test_the_header_block_may_be_a_tuple(addr):
    resp = _fetch(addr, "/tuple-header-block")
    assert resp.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"\r\nx-tup: 1\r\n" in resp


def test_headers_may_be_a_one_shot_iterator(addr):
    resp = _fetch(addr, "/generator-headers")
    assert resp.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"\r\nx-gen: 1\r\n" in resp


# --- asgi_coro_step, the C replacement for ctx.run(coro.send, None) ---------


def test_coro_step_reports_a_return_with_the_sentinel():
    async def done():
        return "value"

    assert asgi_coro_step(done()) is ASGI_CORO_DONE


def test_coro_step_returns_what_the_coroutine_yielded():
    async def suspends():
        await asyncio.sleep(0)

    assert asgi_coro_step(suspends()) is None  # a bare yield


def test_coro_step_propagates_the_coroutines_exception():
    async def raises():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        asgi_coro_step(raises())


def test_coro_step_runs_inside_the_given_context():
    import contextvars

    var = contextvars.ContextVar("var", default="outer")
    ctx = contextvars.copy_context()

    async def setter():
        var.set("inner")

    assert asgi_coro_step(setter(), ctx) is ASGI_CORO_DONE
    assert var.get() == "outer", "the context was not left on the way out"
    assert ctx.run(var.get) == "inner", "the step did not run in the context"


def test_coro_step_leaves_the_context_when_the_step_raises():
    import contextvars

    var = contextvars.ContextVar("var", default="outer")
    ctx = contextvars.copy_context()

    async def raises():
        var.set("inner")
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        asgi_coro_step(raises(), ctx)
    # A context left entered would make the next copy_context().run() raise.
    assert contextvars.copy_context().run(var.get) == "outer"


def test_coro_step_rejects_a_bad_argument_count():
    async def noop():
        pass

    coro = noop()
    try:
        with pytest.raises(TypeError):
            asgi_coro_step(coro, None, None)
    finally:
        coro.close()


def test_coro_step_rejects_a_context_that_is_not_one():
    async def noop():
        pass

    coro = noop()
    try:
        with pytest.raises(TypeError):
            asgi_coro_step(coro, object())
    finally:
        coro.close()
