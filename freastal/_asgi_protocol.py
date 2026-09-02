"""Pure-Python ASGI protocol bridge for freastal.

run_asgi_request() is called from C (asgi_dispatch) once per HTTP request.
It builds the receive/send pair and runs `app(scope, receive, send)`.

Apps that never suspend - the overwhelming majority of request handlers, since
receive() returns immediately and send() calls back into C synchronously - are
driven to completion inline, with no Task and no event-loop step at all.  Apps
that do real async I/O suspend on their first step and are handed to a normal
asyncio Task, which freastal drives from its uv_check_t / uv_poll_t callbacks.
"""

import asyncio

from ._freastal import asgi_send_response


class _Request:
    """The receive/send pair for a single ASGI request.

    One object per request, replacing the two closures and two one-element
    list cells that the callable-per-request version allocated.
    """

    __slots__ = ("_body", "_capsule", "_headers", "_status")

    def __init__(self, body, capsule):
        self._body = body
        self._capsule = capsule
        self._status = None
        self._headers = None

    async def receive(self):
        return {"type": "http.request", "body": self._body, "more_body": False}

    async def send(self, event):
        t = event["type"]
        if t == "http.response.start":
            self._status = event["status"]
            self._headers = list(event.get("headers", []))
        elif t == "http.response.body":
            asgi_send_response(
                self._capsule,
                self._status,
                self._headers,
                event.get("body", b""),
            )


def run_asgi_request(loop, app, scope, body, capsule):
    """Run the ASGI app; return a Task only if it actually suspended.

    Returning None means the app ran to completion inline and the response is
    already on the wire, so the caller has nothing to keep alive.  That is the
    hot path: it skips Task construction and the loop._run_once() step (with
    its selector syscall) that would otherwise be needed just to deliver a
    response the app had already finished producing.

    The caller must have made `loop` the running loop before calling this, so
    that asyncio.get_running_loop() works inside the app.
    """
    req = _Request(body, capsule)
    coro = app(scope, req.receive, req.send)
    try:
        trap = coro.send(None)
    except StopIteration:
        return None
    return loop.create_task(_finish(coro, trap))


async def _finish(coro, trap):
    """Drive a coroutine that already took its first step and suspended.

    Reproduces the handshake asyncio.Task performs between __step and
    __wakeup, for a coroutine whose first step run_asgi_request() already
    took: block on whatever the coroutine yielded, then resume it.

    Failures of an awaited future are deliberately swallowed here - the
    coroutine raises them itself, out of its own future.result(), when it is
    resumed on the next send().  That is also what makes cancellation work:
    cancelling this Task cancels `trap`, and the app sees the CancelledError
    at its own await point.
    """
    try:
        while True:
            if trap is None:
                # A bare `yield` - asyncio.sleep(0) and friends.
                await asyncio.sleep(0)
            elif getattr(trap, "_asyncio_future_blocking", None) is not None:
                trap._asyncio_future_blocking = False
                try:
                    await trap
                except BaseException:  # noqa: BLE001, S110
                    # Intentional: the coroutine raises this itself, out of its
                    # own future.result(), when resumed on the next send().
                    pass
            else:
                raise RuntimeError(f"ASGI app got bad yield: {trap!r}")
            try:
                trap = coro.send(None)
            except StopIteration:
                return
    except BaseException:
        # Cancelled, or the app yielded something asyncio cannot await.
        # Close the coroutine so its finally blocks run and it is not left
        # dangling for the garbage collector to complain about.
        coro.close()
        raise
