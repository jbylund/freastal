"""ASGI lifespan protocol driver.

Runs the app once with ``scope["type"] == "lifespan"`` before the server starts
accepting connections, waits for ``lifespan.startup.complete``, and, when the
server is told to stop, sends ``lifespan.shutdown`` and waits for the app to
acknowledge it.

The lifespan call is a long-lived task: it parks in ``receive()`` for the whole
life of the server and is resumed by the shutdown message.  It is driven by the
same event loop that serves requests, so anything the app starts during startup
(connection pools, background tasks) lives on that loop.

The ``mode`` follows uvicorn's ``lifespan`` option:

``"auto"``  Use lifespan if the app supports it; carry on without it if the app
            does not.  An app that raises before it has even asked for its first
            event is treated as not supporting lifespan (the usual shape is
            ``assert scope["type"] == "http"``).  An app that took part and then
            failed is *not* ignored: serving with a half-initialised app is the
            worse outcome.
``"on"``    Lifespan is required; anything other than a completed startup is
            an error.
``"off"``   Never send a lifespan scope.
"""

import asyncio
import sys
import traceback

MODES = ("auto", "on", "off")

# How long lifespan.shutdown may take before the server stops waiting for it.
# Shorter than the supervisor's patience for a worker to exit (see
# _run_workers) so a stuck app is reported rather than killed mid-sentence.
SHUTDOWN_TIMEOUT = 10.0


class LifespanError(RuntimeError):
    """The app failed startup, or lifespan was required and not provided."""


def _log(msg):
    print(f"[freastal] {msg}", file=sys.stderr, flush=True)


class Lifespan:
    def __init__(self, app, mode="auto", shutdown_timeout=SHUTDOWN_TIMEOUT):
        if mode not in MODES:
            raise ValueError(f"lifespan must be one of {MODES}, not {mode!r}")
        self.app = app
        self.mode = mode
        self.shutdown_timeout = shutdown_timeout
        # Handed to the app as scope["state"]; whatever it stores there during
        # startup is copied into every request scope.
        self.state = {}
        self.active = False

        self._task = None
        self._queue = None
        self._startup = None  # Future: startup.complete / .failed
        self._shutdown = None  # Future: shutdown.complete / .failed
        self._received = False  # the app has asked for an event

    # -- the receive/send pair the app sees ---------------------------------

    async def _receive(self):
        self._received = True
        return await self._queue.get()

    async def _send(self, message):
        kind = message["type"]
        if kind == "lifespan.startup.complete":
            self._settle(self._startup)
        elif kind == "lifespan.startup.failed":
            self._settle(self._startup, message.get("message", ""))
        elif kind == "lifespan.shutdown.complete":
            self._settle(self._shutdown)
        elif kind == "lifespan.shutdown.failed":
            self._settle(self._shutdown, message.get("message", ""))
        else:
            raise RuntimeError(f"unexpected lifespan message type {kind!r}")

    @staticmethod
    def _settle(fut, failure=None):
        if fut.done():
            return
        if failure is None:
            fut.set_result(None)
        else:
            fut.set_exception(LifespanError(failure))

    async def _run(self):
        scope = {
            "type": "lifespan",
            "asgi": {"version": "3.0", "spec_version": "2.0"},
            "state": self.state,
        }
        await self.app(scope, self._receive, self._send)

    # -- startup ------------------------------------------------------------

    async def startup(self):
        """Run startup.  True if the app took part, False if it does not support
        lifespan.  Raises LifespanError when startup failed or was required."""
        if self.mode == "off":
            return False

        loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue()
        self._startup = loop.create_future()
        self._shutdown = loop.create_future()
        self._task = loop.create_task(self._run())
        self._task.add_done_callback(self._on_done)
        self._queue.put_nowait({"type": "lifespan.startup"})

        await asyncio.wait(
            [self._startup, self._task], return_when=asyncio.FIRST_COMPLETED
        )

        if self._startup.done():
            try:
                self._startup.result()
            except LifespanError as exc:
                await self._reap()
                detail = f": {exc}" if str(exc) else ""
                raise LifespanError(f"lifespan startup failed{detail}") from None
            self.active = True
            return True

        # The task ended without ever answering the startup event.
        exc = self._task.exception() if not self._task.cancelled() else None
        await self._reap()
        if self.mode == "on":
            raise LifespanError(
                "lifespan is required but the app did not complete startup"
                + (f" ({exc!r})" if exc else "")
            ) from exc
        if exc is not None and self._received:
            raise LifespanError(f"lifespan startup failed: {exc!r}") from exc
        _log("ASGI app does not support lifespan; continuing without it")
        return False

    def _on_done(self, task):
        # Retrieve the result so a failure is reported once, here, rather than
        # as an "exception was never retrieved" warning at garbage collection.
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None and self.active and not self._shutdown.done():
            _log(f"ASGI lifespan task died: {exc!r}")
            traceback.print_exception(exc, file=sys.stderr)

    async def _reap(self):
        task = self._task
        if task is not None and not task.done():
            task.cancel()
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)

    # -- shutdown -----------------------------------------------------------

    async def shutdown(self):
        """Deliver lifespan.shutdown and wait (bounded) for the app's answer."""
        if not self.active:
            return
        self.active = False
        task = self._task
        try:
            if not task.done():
                self._queue.put_nowait({"type": "lifespan.shutdown"})
                waiter = asyncio.ensure_future(
                    asyncio.wait(
                        [self._shutdown, task], return_when=asyncio.FIRST_COMPLETED
                    )
                )
                try:
                    await asyncio.wait_for(waiter, self.shutdown_timeout)
                except asyncio.TimeoutError:
                    _log(
                        "ASGI lifespan.shutdown did not finish within "
                        f"{self.shutdown_timeout:g}s; exiting anyway"
                    )
            if self._shutdown.done():
                try:
                    self._shutdown.result()
                except LifespanError as exc:
                    _log(f"ASGI lifespan shutdown failed: {exc}")
            elif task.done() and not task.cancelled() and task.exception():
                # Died while shutting down, without answering.
                _log(f"ASGI lifespan shutdown failed: {task.exception()!r}")
        finally:
            await self._reap()
