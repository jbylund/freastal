"""ASGI lifespan: startup before serving, shutdown on SIGTERM/SIGINT.

Server tests run freastal in a child process and observe it through a log file
the app appends to, since startup and shutdown are not visible on the wire.
"""

import asyncio
import multiprocessing
import os
import signal
import socket
import time

import pytest
from conftest import _free_port, _wait_for_port

import freastal
from freastal import _lifespan


class LifespanApp:
    """An ASGI app whose lifespan behaviour is chosen by `startup`/`shutdown`.

    A class rather than a closure so it can be pickled for workers>1.
    """

    def __init__(self, logfile, startup="ok", shutdown="ok"):
        self.logfile = logfile
        self.startup = startup
        self.shutdown = shutdown

    def _log(self, line):
        with open(self.logfile, "a") as f:
            f.write(line + "\n")

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            return await self._http(scope, send)
        if self.startup == "unsupported":
            raise NotImplementedError(scope["type"])
        assert scope["type"] == "lifespan"
        assert scope["asgi"]["spec_version"] == "2.0"
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                self._log(f"startup pid={os.getpid()}")
                if self.startup == "fail":
                    await send({"type": "lifespan.startup.failed", "message": "boom"})
                    return
                if self.startup == "raise":
                    raise ValueError("startup blew up")
                scope["state"]["greeting"] = "hello"
                # A timer left pending when startup ends: it has to fire on an
                # idle server, with no request to wake the loop.
                loop = asyncio.get_running_loop()
                loop.call_later(0.2, self._log, "tick")
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                self._log("shutdown")
                if self.shutdown == "fail":
                    await send({"type": "lifespan.shutdown.failed", "message": "no"})
                else:
                    await send({"type": "lifespan.shutdown.complete"})
                return

    async def _http(self, scope, send):
        state = scope.get("state")
        body = f"state={state.get('greeting') if state is not None else None}"
        if state is not None:
            state["greeting"] = "mutated"  # must not leak into the next request
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body.encode()})


def _serve(port, app, lifespan="auto", workers=1):
    freastal.serve_asgi(
        app,
        host="127.0.0.1",
        port=port,
        workers=workers,
        reuse_port=False,
        lifespan=lifespan,
    )


def _start(app, lifespan="auto", workers=1, wait=True):
    port = _free_port()
    p = multiprocessing.Process(target=_serve, args=(port, app, lifespan, workers))
    p.start()
    if wait:
        _wait_for_port("127.0.0.1", port)
    return p, port


def _stop(p):
    if p.is_alive():
        p.terminate()
    p.join(timeout=15)
    if p.is_alive():
        p.kill()
        p.join()


def _fetch(port, path="/"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".encode()
        )
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks)


def _lines(path):
    try:
        with open(path) as f:
            return f.read().split()
    except FileNotFoundError:
        return []


@pytest.fixture
def logfile(tmp_path):
    return str(tmp_path / "log")


# --- server behaviour --------------------------------------------------------


def test_startup_runs_before_requests_and_state_reaches_the_request(logfile):
    p, port = _start(LifespanApp(logfile))
    try:
        assert _lines(logfile)[0] == "startup"  # already ran: the port is open
        assert _fetch(port).endswith(b"state=hello")
        # The handler overwrote its copy; the next request gets a fresh one.
        assert _fetch(port).endswith(b"state=hello")
    finally:
        _stop(p)


def test_timer_scheduled_during_startup_fires_on_an_idle_server(logfile):
    # Deliberately never connects: a connection wakes the loop and would arm the
    # timer by itself, hiding the bug this guards against.
    p, _ = _start(LifespanApp(logfile), wait=False)
    try:
        deadline = time.monotonic() + 5
        while "tick" not in _lines(logfile) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert "tick" in _lines(logfile)
    finally:
        _stop(p)


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_signal_delivers_shutdown_and_exits_cleanly(logfile, sig):
    p, port = _start(LifespanApp(logfile))
    assert _fetch(port).endswith(b"state=hello")
    os.kill(p.pid, sig)
    p.join(timeout=10)
    assert not p.is_alive()
    assert p.exitcode == 0
    assert "shutdown" in _lines(logfile)


def test_failed_shutdown_still_exits(logfile):
    p, _ = _start(LifespanApp(logfile, shutdown="fail"))
    os.kill(p.pid, signal.SIGTERM)
    p.join(timeout=10)
    assert p.exitcode == 0
    assert "shutdown" in _lines(logfile)


def test_app_without_lifespan_support_still_serves(logfile):
    p, port = _start(LifespanApp(logfile, startup="unsupported"))
    try:
        assert _fetch(port).endswith(b"state=None")
    finally:
        _stop(p)


def test_app_without_lifespan_support_still_dies_on_sigterm(logfile):
    # No lifespan means signals keep their default disposition: the kernel
    # kills an idle server, as it always did.
    p, _ = _start(LifespanApp(logfile, startup="unsupported"))
    os.kill(p.pid, signal.SIGTERM)
    p.join(timeout=10)
    assert not p.is_alive()


@pytest.mark.parametrize("startup", ["fail", "raise"])
def test_failed_startup_exits_nonzero_without_serving(logfile, startup):
    p, port = _start(LifespanApp(logfile, startup=startup), wait=False)
    p.join(timeout=10)
    assert p.exitcode not in (0, None)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


def test_lifespan_on_requires_support(logfile):
    p, _ = _start(LifespanApp(logfile, startup="unsupported"), "on", wait=False)
    p.join(timeout=10)
    assert p.exitcode not in (0, None)


def test_lifespan_off_sends_no_scope(logfile):
    p, port = _start(LifespanApp(logfile), "off")
    try:
        assert _fetch(port).endswith(b"state=None")
        assert _lines(logfile) == []
    finally:
        _stop(p)


def test_every_worker_runs_its_own_lifespan(logfile):
    p, port = _start(LifespanApp(logfile), workers=2)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            starts = [x for x in _lines(logfile) if x.startswith("pid=")]
            if len(starts) >= 2:
                break
            time.sleep(0.05)
        assert len(set(starts)) == 2
        assert _fetch(port).endswith(b"state=hello")
        os.kill(p.pid, signal.SIGTERM)
        p.join(timeout=20)
        assert p.exitcode == 0
        assert _lines(logfile).count("shutdown") == 2
    finally:
        _stop(p)


def test_rejects_unknown_lifespan_mode():
    with pytest.raises(ValueError, match="lifespan"):
        freastal.serve_asgi(lambda *a: None, lifespan="sometimes")


# --- the driver on its own ---------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


def test_driver_completes_startup_and_shutdown():
    async def app(scope, receive, send):
        assert (await receive())["type"] == "lifespan.startup"
        scope["state"]["x"] = 1
        await send({"type": "lifespan.startup.complete"})
        assert (await receive())["type"] == "lifespan.shutdown"
        await send({"type": "lifespan.shutdown.complete"})

    async def go():
        ls = _lifespan.Lifespan(app)
        assert await ls.startup() is True
        assert ls.state == {"x": 1}
        await ls.shutdown()
        assert not ls.active

    _run(go())


def test_driver_reports_startup_failed_message():
    async def app(scope, receive, send):
        await receive()
        await send({"type": "lifespan.startup.failed", "message": "db down"})

    with pytest.raises(_lifespan.LifespanError, match="db down"):
        _run(_lifespan.Lifespan(app).startup())


def test_driver_treats_an_early_raise_as_unsupported_in_auto():
    async def app(scope, receive, send):
        raise RuntimeError("only http")

    assert _run(_lifespan.Lifespan(app).startup()) is False


def test_driver_treats_a_raise_after_receive_as_failed_startup():
    async def app(scope, receive, send):
        await receive()
        raise RuntimeError("half initialised")

    with pytest.raises(_lifespan.LifespanError, match="half initialised"):
        _run(_lifespan.Lifespan(app).startup())


def test_driver_on_mode_rejects_a_clean_return():
    async def app(scope, receive, send):
        return

    with pytest.raises(_lifespan.LifespanError):
        _run(_lifespan.Lifespan(app, "on").startup())


def test_driver_gives_up_on_a_shutdown_that_hangs(capsys):
    async def app(scope, receive, send):
        await receive()
        await send({"type": "lifespan.startup.complete"})
        await receive()
        await asyncio.sleep(3600)

    async def go():
        ls = _lifespan.Lifespan(app, shutdown_timeout=0.1)
        await ls.startup()
        start = time.monotonic()
        await ls.shutdown()
        return time.monotonic() - start

    assert _run(go()) < 2
    assert "did not finish" in capsys.readouterr().err


def test_driver_rejects_unexpected_message_types():
    async def app(scope, receive, send):
        await receive()
        await send({"type": "lifespan.bogus"})

    # The app took part and then failed, so this is a failed startup.
    with pytest.raises(_lifespan.LifespanError, match="bogus"):
        _run(_lifespan.Lifespan(app).startup())
