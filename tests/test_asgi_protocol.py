"""Unit tests for the ASGI bridge's eager-drive fast path and its fallback.

These drive freastal._asgi_protocol against a plain asyncio loop, with the C
send hook stubbed out, so the suspend/resume handshake in _finish() can be
tested without a live server.
"""

import asyncio
import contextvars
import sys

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


def start(loop, app, body=b""):
    """Dispatch one request exactly the way asgi_dispatch() does.

    The C caller makes the loop current for the eager step and drops it again
    before anything else steps the loop, and the emulation has to match:
    asyncio.current_task() is reached through the running loop.
    """
    asyncio._set_running_loop(loop)
    try:
        return run_asgi_request(loop, app, SCOPE, body, object())
    finally:
        asyncio._set_running_loop(None)


def run(loop, app, body=b""):
    """Dispatch one request; return the Task, driving it to completion."""
    task = start(loop, app, body)
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
        start(loop, app)
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

    task = start(loop, app)
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

    task = start(loop, app)
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

    task = start(loop, app)
    with pytest.raises(RuntimeError, match="bad yield"):
        loop.run_until_complete(task)


# --- request-scoped state --------------------------------------------------
#
# The eager path runs the app on the dispatch stack, so nothing else sets up
# the per-task state asyncio would normally hand it.

TENANT = contextvars.ContextVar("tenant", default="<unset>")


def test_contextvar_does_not_leak_into_the_next_request(loop, sent):
    """One request's ContextVar.set() must not be visible to the next.

    Handlers run back to back on one worker; a set() that landed in the
    server's own context would hand the next caller the previous caller's
    trace id, tenant or logging context.
    """
    seen = []

    async def app(scope, receive, send):
        seen.append(TENANT.get())
        TENANT.set("tenant-a")
        await _reply(send)

    run(loop, app)
    run(loop, app)
    assert seen == ["<unset>", "<unset>"], "request-scoped state leaked"


def test_contextvar_does_not_leak_into_the_server_context(loop, sent):
    async def app(scope, receive, send):
        TENANT.set("tenant-a")
        await _reply(send)

    run(loop, app)
    assert TENANT.get() == "<unset>", "app dirtied the server's own context"


def test_contextvar_set_before_suspending_survives_the_await(loop, sent):
    """The continuation must resume in the eager step's own context."""
    seen = []

    async def app(scope, receive, send):
        TENANT.set("before")
        fut = loop.create_future()
        loop.call_soon(fut.set_result, None)
        await fut
        seen.append(TENANT.get())
        TENANT.set("after")
        seen.append(TENANT.get())
        await _reply(send)

    assert run(loop, app) is not None
    assert seen == ["before", "after"]
    assert TENANT.get() == "<unset>"


def test_contextvar_set_after_suspending_does_not_leak(loop, sent):
    seen = []

    async def app(scope, receive, send):
        seen.append(TENANT.get())
        await asyncio.sleep(0)
        TENANT.set("tenant-a")
        await _reply(send)

    run(loop, app)
    run(loop, app)
    assert seen == ["<unset>", "<unset>"]


# --- current task ----------------------------------------------------------


def test_current_task_is_set_during_the_eager_step(loop, sent):
    seen = []

    async def app(scope, receive, send):
        seen.append(asyncio.current_task())
        await _reply(send)

    assert run(loop, app) is None
    assert seen[0] is not None, "app ran with no current task"
    assert isinstance(seen[0], asyncio.Task)


def test_current_task_is_set_after_suspending(loop, sent):
    seen = []

    async def app(scope, receive, send):
        await asyncio.sleep(0)
        seen.append(asyncio.current_task())
        await _reply(send)

    assert run(loop, app) is not None
    assert seen[0] is not None


def test_wait_for_works_on_the_eager_path(loop, sent):
    """On 3.12+ wait_for is built on asyncio.timeout, which needs a task."""

    async def app(scope, receive, send):
        fut = loop.create_future()
        loop.call_soon(fut.set_result, b"waited")
        await _reply(send, body=await asyncio.wait_for(fut, 5))

    assert run(loop, app) is not None
    assert sent[0][2] == b"waited"


@pytest.mark.skipif(sys.version_info < (3, 11), reason="asyncio.timeout is 3.11+")
def test_asyncio_timeout_works_on_the_eager_path(loop, sent):
    async def app(scope, receive, send):
        async with asyncio.timeout(5):
            fut = loop.create_future()
            loop.call_soon(fut.set_result, b"in-time")
            body = await fut
        await _reply(send, body=body)

    assert run(loop, app) is not None
    assert sent[0][2] == b"in-time"


@pytest.mark.skipif(sys.version_info < (3, 11), reason="asyncio.timeout is 3.11+")
def test_asyncio_timeout_entered_eagerly_still_expires(loop, sent):
    """Timeout takes current_task() eagerly but cancels it much later.

    __aenter__ captures the stand-in during the first step; _on_timeout fires
    from a loop callback, by which point the request is a real Task.  If the
    stand-in's cancel() did not forward, this would hang rather than raise.
    """

    async def app(scope, receive, send):
        try:
            async with asyncio.timeout(0.05):
                await loop.create_future()  # never resolves
        except TimeoutError:
            await _reply(send, body=b"expired")

    task = start(loop, app)
    assert task is not None
    loop.run_until_complete(asyncio.wait_for(task, 3))
    assert sent[0][2] == b"expired"


def test_wait_for_entered_eagerly_still_times_out(loop, sent):
    async def app(scope, receive, send):
        try:
            await asyncio.wait_for(loop.create_future(), 0.05)
        except (asyncio.TimeoutError, TimeoutError):
            await _reply(send, body=b"expired")

    task = start(loop, app)
    assert task is not None
    loop.run_until_complete(asyncio.wait_for(task, 3))
    assert sent[0][2] == b"expired"


def test_cancelling_the_standin_task_reaches_the_running_app(loop, sent):
    """Whatever the app captured from current_task() must still cancel it."""
    captured = []
    cleaned = []

    async def app(scope, receive, send):
        captured.append(asyncio.current_task())
        try:
            await loop.create_future()  # never resolves
        except asyncio.CancelledError:
            cleaned.append("cancelled")
            raise

    task = start(loop, app)
    assert task is not None
    assert captured[0] is not None
    loop.call_soon(captured[0].cancel)
    with pytest.raises(asyncio.CancelledError):
        # Bounded: a stand-in that dropped the cancel would wait forever.
        loop.run_until_complete(asyncio.wait_for(task, 3))
    assert cleaned == ["cancelled"]


def test_cancel_during_the_eager_step_is_replayed_onto_the_task(loop, sent):
    """A cancel that arrives before there is a Task must not be dropped."""
    cleaned = []

    async def app(scope, receive, send):
        asyncio.current_task().cancel()
        try:
            await loop.create_future()  # never resolves
        finally:
            cleaned.append("closed")

    task = start(loop, app)
    assert task is not None
    with pytest.raises(asyncio.CancelledError):
        loop.run_until_complete(asyncio.wait_for(task, 3))
    assert cleaned == ["closed"]


def test_the_standin_task_is_dropped_after_the_request(loop, sent):
    """A current task left behind would break the next task the loop steps."""

    async def app(scope, receive, send):
        await _reply(send)

    assert run(loop, app) is None
    asyncio._set_running_loop(loop)
    try:
        assert asyncio.current_task() is None
    finally:
        asyncio._set_running_loop(None)


def test_the_standin_task_is_dropped_when_the_app_raises(loop, sent):
    async def app(scope, receive, send):
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        start(loop, app)
    asyncio._set_running_loop(loop)
    try:
        assert asyncio.current_task() is None
    finally:
        asyncio._set_running_loop(None)
