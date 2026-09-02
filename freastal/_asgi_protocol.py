"""Pure-Python ASGI protocol bridge for freastal.

run_asgi_request() is called from C (asgi_dispatch) once per HTTP request.
It builds the receive/send pair and runs `app(scope, receive, send)`.

Apps that never suspend - the overwhelming majority of request handlers, since
receive() returns immediately and send() calls back into C synchronously - are
driven to completion inline, with no Task and no event-loop step at all.  Apps
that do real async I/O suspend on their first step and are handed to a normal
asyncio Task, which freastal drives from its uv_check_t / uv_poll_t callbacks.

Running the app on the dispatch stack means asyncio has set up none of the
per-task state the app is entitled to expect: no context of its own and no
current task.  This module supplies both itself - see _Request and
run_asgi_request - because leaving them out is not a cosmetic problem but a
correctness one in three separate ways.
"""

import asyncio
import contextvars
import sys

# Private, but present and unchanged from 3.10 through 3.14, and the only way
# to publish a current task for code that is not running inside a Task.
from asyncio.tasks import _enter_task, _leave_task

from ._freastal import ASGI_CORO_DONE as _DONE
from ._freastal import asgi_coro_step as _step
from ._freastal import asgi_send_response

# loop.create_task(..., context=...) is 3.11+.  Older versions have to be told
# which context to use by entering it around the Task's construction.
_CREATE_TASK_TAKES_CONTEXT = sys.version_info >= (3, 11)


class _Request(asyncio.Task):
    """The receive/send pair for a single ASGI request, doubling as its task.

    One object per request, replacing the two closures and two one-element
    list cells that the callable-per-request version allocated.

    It subclasses asyncio.Task so that asyncio.current_task() has something to
    report while the app runs inline.  A None current task is not merely
    cosmetic: asyncio.timeouts.Timeout.__aenter__ - and so asyncio.wait_for()
    on 3.12+, which is implemented on top of it - and asyncio.TaskGroup both
    open by taking current_task() and raise RuntimeError when it is None, so an
    app whose first await is a wait_for() cannot run at all without this.
    Folding the stand-in into the object the request already allocates keeps
    the eager path at one object per request; constructing a real Task is
    precisely the allocation-and-scheduling work that path exists to skip.

    asyncio.Task.__init__ is deliberately never called, so the C base stays
    zeroed.  Most inherited methods read that as a pending future and behave
    (done() is False, cancelling() is 0), but anything that dereferences the
    absent future state does not: Future.__repr__ raises "Future object is not
    initialized" - and _enter_task() reprs the task on its error path - while
    Task.get_coro() segfaults outright on 3.10.  Those two are overridden
    below, and nothing else added here may reach into the base.
    """

    __slots__ = (
        "_body",
        "_cancel",
        "_capsule",
        "_headers",
        "_status",
        "_task",
    )

    def __init__(self, body, capsule):
        self._body = body
        self._capsule = capsule
        self._status = None
        self._headers = None
        self._task = None  # continuation Task, once the app has suspended
        self._cancel = None  # cancel() that arrived before there was one

    async def receive(self):
        return {"type": "http.request", "body": self._body, "more_body": False}

    async def send(self, event):
        t = event["type"]
        if t == "http.response.start":
            self._status = event["status"]
            h = event.get("headers", ())
            # A list can be handed to asgi_send_response() as it stands: it
            # only reads the pairs, and reads them before send() returns, so
            # copying it bought nothing.  Everything else the spec allows (it
            # asks only for an iterable) still has to be materialised - the C
            # side indexes a list, and an iterator would be consumed anyway.
            self._headers = h if type(h) is list else list(h)
        elif t == "http.response.body":
            asgi_send_response(
                self._capsule,
                self._status,
                self._headers,
                event.get("body", b""),
            )

    # --- the asyncio.Task face of a request ---------------------------------

    def __repr__(self):
        return "<freastal ASGI request>"

    def get_coro(self):
        # Task.get_coro() reads the C coroutine slot __init__ never filled in;
        # on 3.10 that is a segfault rather than an exception.
        return None

    def get_name(self):
        return "freastal-asgi-request"

    def cancel(self, msg=None):
        """Cancel the request, wherever it has got to.

        Whoever captured current_task() during the eager step almost never
        cancels it there: a Timeout's _on_timeout and a TaskGroup's abort both
        fire from a later loop callback, by which point the request is a real
        Task.  Forwarding is what makes them work at all - a stand-in whose
        cancel() quietly did nothing would turn an expiring asyncio.timeout()
        into a hang, which is a worse failure than the RuntimeError it
        replaces.
        """
        task = self._task
        if task is not None:
            return task.cancel(msg)
        # Cancelled during the eager step, before there is a Task to carry it.
        # Replayed by run_asgi_request() if the app goes on to suspend; if it
        # finishes inline instead, there is nothing left to cancel.
        self._cancel = (msg,)
        return True

    def cancelling(self):
        task = self._task
        return task.cancelling() if task is not None else 0

    def uncancel(self):
        task = self._task
        return task.uncancel() if task is not None else 0


def run_asgi_request(loop, app, scope, body, capsule):
    """Run the ASGI app; return a Task only if it actually suspended.

    Returning None means the app ran to completion inline and the response is
    already on the wire, so the caller has nothing to keep alive.  That is the
    hot path: it skips Task construction and the loop._run_once() step (with
    its selector syscall) that would otherwise be needed just to deliver a
    response the app had already finished producing.

    The caller must have made `loop` the running loop before calling this, so
    that asyncio.get_running_loop() works inside the app.

    The app gets a context of its own, and `req` published as the current
    task, for the duration of that first step.  The context is what keeps
    requests isolated from each other: a ContextVar.set() run in the server's
    own context would still be there for the *next* request this worker
    handles, so one caller's trace id, tenant or logging context would show up
    in another's.
    """
    req = _Request(body, capsule)
    coro = app(scope, req.receive, req.send)
    ctx = contextvars.copy_context()
    _enter_task(loop, req)
    try:
        trap = _step(coro, ctx)
    finally:
        _leave_task(loop, req)
    if trap is _DONE:
        return None

    # The continuation must resume in the *same* context as the eager step, or
    # a ContextVar set before the app's first await would vanish across it.
    fin = _finish(req, coro, trap)
    if _CREATE_TASK_TAKES_CONTEXT:
        task = loop.create_task(fin, context=ctx)
    else:
        # 3.10 has no context= argument; Task.__init__ copies whatever context
        # is current instead, so build the Task from inside the request's.
        task = ctx.run(loop.create_task, fin)
    req._task = task
    if req._cancel is not None:
        # An app that cancelled itself during the eager step.  Hand the cancel
        # to the loop rather than straight to the Task: cancelling a Task that
        # has not been stepped yet throws into _finish before it starts, so
        # _finish never gets to close the app's coroutine and the app's own
        # cleanup never runs.  One callback later, _finish is parked on `trap`
        # and cancel() cancels that instead - which is exactly what
        # Task.__step does for a task that cancels itself.
        loop.call_soon(task.cancel, *req._cancel)
    return task


async def _finish(req, coro, trap):
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
            trap = _step(coro)
            if trap is _DONE:
                return
    except BaseException:
        # Cancelled, or the app yielded something asyncio cannot await.
        # Close the coroutine so its finally blocks run and it is not left
        # dangling for the garbage collector to complain about.
        coro.close()
        raise
    finally:
        # req -> this Task -> this coroutine -> the app's frame -> req.send is
        # a cycle only the collector could break, and the forwarding target is
        # pointless once the Task is done anyway.
        req._task = None
