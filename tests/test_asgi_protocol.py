"""Unit tests for the ASGI bridge's eager-drive fast path and its fallback.

These drive freastal._asgi_protocol against a plain asyncio loop, with the C
send hook stubbed out, so the suspend/resume handshake in _finish() can be
tested without a live server.
"""

import asyncio

import pytest

from freastal import _asgi_protocol
from freastal._asgi_protocol import run_asgi_request


@pytest.fixture
def loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()
    asyncio.set_event_loop(None)


@pytest.fixture
def sent(monkeypatch):
    """Capture asgi_send_response() calls instead of writing to a socket."""
    calls = []
    monkeypatch.setattr(
        _asgi_protocol,
        "asgi_send_response",
        lambda capsule, status, headers, body: calls.append((status, headers, body)),
    )
    # _Request.send resolves the name at call time from the module globals,
    # so patching the module attribute is enough.
    return calls


SCOPE = {"type": "http", "method": "GET", "path": "/"}


async def _reply(send, status=200, body=b"ok"):
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [[b"content-type", b"text/plain"]],
        }
    )
    await send({"type": "http.response.body", "body": body})


def run(loop, app, body=b""):
    """Dispatch one request; return the Task, driving it to completion."""
    task = run_asgi_request(loop, app, SCOPE, body, object())
    if task is not None:
        loop.run_until_complete(task)
    return task


# --- fast path -------------------------------------------------------------


def test_sync_app_completes_inline_without_a_task(loop, sent):
    async def app(scope, receive, send):
        await _reply(send)

    assert run(loop, app) is None, "non-suspending app should not need a Task"
    assert sent == [(200, [[b"content-type", b"text/plain"]], b"ok")]


def test_receive_returns_the_request_body(loop, sent):
    async def app(scope, receive, send):
        event = await receive()
        assert event["type"] == "http.request"
        assert event["more_body"] is False
        await _reply(send, body=event["body"])

    assert run(loop, app, body=b"payload") is None
    assert sent[0][2] == b"payload"


def test_sync_app_exception_propagates_to_the_caller(loop, sent):
    async def app(scope, receive, send):
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        run_asgi_request(loop, app, SCOPE, b"", object())
    assert sent == []


# --- fallback path: apps that actually suspend ------------------------------


def test_suspending_app_returns_a_task_and_still_replies(loop, sent):
    async def app(scope, receive, send):
        fut = loop.create_future()
        loop.call_soon(fut.set_result, b"late")
        await _reply(send, body=await fut)

    task = run(loop, app)
    assert task is not None, "suspending app must be handed to a Task"
    assert sent == [(200, [[b"content-type", b"text/plain"]], b"late")]


def test_suspending_app_survives_many_awaits(loop, sent):
    async def app(scope, receive, send):
        total = 0
        for i in range(5):
            fut = loop.create_future()
            loop.call_soon(fut.set_result, i)
            total += await fut
        await _reply(send, body=str(total).encode())

    assert run(loop, app) is not None
    assert sent[0][2] == b"10"


def test_bare_yield_is_rescheduled(loop, sent):
    async def app(scope, receive, send):
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await _reply(send)

    assert run(loop, app) is not None
    assert sent[0][2] == b"ok"


def test_awaited_failure_is_raised_inside_the_app(loop, sent):
    seen = []

    async def app(scope, receive, send):
        fut = loop.create_future()
        loop.call_soon(fut.set_exception, ValueError("downstream"))
        try:
            await fut
        except ValueError as exc:
            seen.append(str(exc))
        await _reply(send)

    assert run(loop, app) is not None
    assert seen == ["downstream"], "app must see the awaited future's exception"
    assert sent[0][2] == b"ok"


def test_exception_after_suspension_fails_the_task(loop, sent):
    async def app(scope, receive, send):
        fut = loop.create_future()
        loop.call_soon(fut.set_result, None)
        await fut
        raise ValueError("late boom")

    task = run_asgi_request(loop, app, SCOPE, b"", object())
    with pytest.raises(ValueError, match="late boom"):
        loop.run_until_complete(task)


def test_cancelling_the_task_runs_the_app_cleanup(loop, sent):
    cleaned = []

    async def app(scope, receive, send):
        try:
            await loop.create_future()  # never resolves
        except asyncio.CancelledError:
            cleaned.append("cancelled")
            raise
        finally:
            cleaned.append("finally")

    task = run_asgi_request(loop, app, SCOPE, b"", object())
    assert task is not None
    loop.call_soon(task.cancel)
    with pytest.raises(asyncio.CancelledError):
        loop.run_until_complete(task)
    assert cleaned == ["cancelled", "finally"]


def test_bad_yield_fails_the_task(loop, sent):
    class Weird:
        def __await__(self):
            yield "not a future"

    async def app(scope, receive, send):
        await Weird()

    task = run_asgi_request(loop, app, SCOPE, b"", object())
    with pytest.raises(RuntimeError, match="bad yield"):
        loop.run_until_complete(task)
