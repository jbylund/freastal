"""The serve()/serve_asgi() argument grid: workers x reuse_port x entry point.

Issue #48's two bugs -- a reuse_port=True default that cannot bind outside
Linux/FreeBSD/DragonFly/Solaris, and a worker target that cannot pickle under
spawn -- both survived because every other test in this tree pins the single
configuration that happens to work: workers=1, reuse_port=False, passed
explicitly.  Nothing exercised a default argument and nothing started a second
worker, so neither bug could be observed.

These tests run the grid instead of one cell, and they run real servers over
real sockets: a bug that only shows up when a listening socket is actually
bound, or when multiprocessing actually pickles a target, is invisible to a
mock.

Process and port hygiene, since every test here spawns servers:

  * Ports come from _free_port(), which binds :0 and closes.  That is racy by
    construction, so _serve() retries on a fresh port when the child never
    reaches the listening state -- but only when the child is still alive.  A
    child that has already exited is a real failure and is reported, not retried.
  * Every server is started inside the serving() context manager, which reaps
    the parent on the way out (terminate, join, then kill) and fails the test if
    it will not die.  A leaked server process would keep a port bound and make
    every later test in the session flaky.
  * Server parents are started with daemon=False, because a daemonic process is
    not allowed to have children of its own and the whole point here is that
    workers>1 spawns some.  That means multiprocessing would join them at
    interpreter exit -- i.e. hang pytest -- if one ever escaped, so
    _no_stray_servers below is a session-scoped backstop that kills whatever
    the per-test cleanup missed and says so.
  * Multi-worker servers report their pid in the response body so the workers
    (grandchildren of pytest) can be checked for the same thing.
"""

import inspect
import multiprocessing as mp
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import httpx
import pytest

import freastal
from freastal import _freastal

HOST = "127.0.0.1"

# Kernels that spread new connections across the sockets of an SO_REUSEPORT
# group.  This is libuv's own list for UV_TCP_REUSEPORT, and it is a platform
# property rather than something a runtime probe can answer: macOS accepts
# SO_REUSEPORT on a TCP listener and then delivers every connection to one
# socket in the group, so a probe that only checks setsockopt+bind would say
# "supported" and be wrong in the way that matters.
#
# Ask the extension, exactly as freastal does. A platform table here would be
# the very thing the implementation stopped doing, and it is wrong on more than
# macOS: GitHub's ubuntu runners carry a libuv with no UV_TCP_REUSEPORT at all,
# so "linux" is not the capability either.
KERNEL_LOAD_BALANCES = bool(_freastal.reuse_port_supported())

requires_load_balancing = pytest.mark.skipif(
    not KERNEL_LOAD_BALANCES,
    reason=(
        f"libuv here will not honour UV_TCP_REUSEPORT ({sys.platform}); either "
        "the kernel does not load-balance or this libuv has no such flag. "
        "reuse_port=True is refused, see test_reuse_port_true_is_refused"
    ),
)


# ---------------------------------------------------------------------------
# Apps and the child-process entry point.  Both must be importable by name:
# under the spawn start method multiprocessing pickles the target by module
# and qualname, so a closure or a lambda here would reproduce issue #48's
# second bug inside the test suite itself.
# ---------------------------------------------------------------------------


def _wsgi_pid_app(environ, start_response):
    body = str(os.getpid()).encode()
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [body]


async def _asgi_pid_app(scope, receive, send):
    if scope["type"] != "http":
        return
    body = str(os.getpid()).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [[b"content-type", b"text/plain"]],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _serve_target(kind, kwargs):
    if kind == "wsgi":
        freastal.serve(_wsgi_pid_app, **kwargs)
    else:
        freastal.serve_asgi(_asgi_pid_app, **kwargs)


def _serve_target_forcing_reuse_port(kind, kwargs):
    """_serve_target with the platform veto lifted, to reach the other branch.

    _run_workers takes one of two shapes: one SO_REUSEPORT socket per worker,
    or one shared socket for all of them.  Which one runs is decided by the
    platform, so on any single machine half of that code is unreachable.  This
    lifts the veto in the child (it re-imports under spawn, so patching in the
    parent would not survive) to get the per-worker-socket shape exercised
    here.  What it can prove is that the shape binds, starts and serves; what
    it cannot prove is that the kernel spreads the load, which on macOS it
    demonstrably does not.
    """
    freastal._kernel_load_balances_reuse_port = lambda: True
    _serve_target(kind, kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def _wait_until_serving(proc, port, timeout=10.0):
    """True once the port answers; False if it never does or the child dies."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.exitcode is not None:
            return False
        try:
            with socket.create_connection((HOST, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.02)
    return False


def _reap(proc, timeout=5.0):
    """Stop a server process for good, and say so if it will not stop."""
    if proc.exitcode is None:
        proc.terminate()
        proc.join(timeout)
    if proc.exitcode is None:
        proc.kill()
        proc.join(timeout)
    assert proc.exitcode is not None, f"server pid={proc.pid} survived SIGKILL"


# Only the servers this module started.  multiprocessing.active_children() is
# not a substitute: conftest's session-scoped wsgi_url/asgi_url servers are in
# there too, and killing those takes the rest of the suite down with them.
_STARTED = []


def _start_server(kind, kwargs, target=_serve_target):
    """Start a server parent.  Non-daemonic: it has to be able to fork workers."""
    proc = mp.Process(target=target, args=(kind, kwargs), daemon=False)
    proc.start()
    _STARTED.append(proc)
    return proc


@pytest.fixture(scope="module", autouse=True)
def _no_stray_servers():
    """Backstop: never leave a non-daemonic server behind for atexit to join on."""
    yield
    strays = [p for p in _STARTED if p.is_alive()]
    for p in strays:
        p.kill()
        p.join(5)
    assert not strays, f"server processes leaked past their tests: {strays}"


@contextmanager
def serving(kind, _target=_serve_target, **kwargs):
    """Run freastal in a child process and yield its base URL.

    Retries on a fresh port when the child is alive but the port never came up,
    which is the ephemeral-port race and not a bug in the server.
    """
    target = _target
    last = None
    for _ in range(3):
        port = _free_port()
        proc = _start_server(kind, {"host": HOST, "port": port, **kwargs}, target)
        if _wait_until_serving(proc, port):
            try:
                yield f"http://{HOST}:{port}"
            finally:
                _reap(proc)
            return
        exitcode = proc.exitcode
        _reap(proc)
        if exitcode is not None:
            # The child died rather than losing a port race: a real failure.
            pytest.fail(
                f"freastal {kind} server exited with {exitcode} before listening; "
                f"kwargs={kwargs} (child traceback is in the captured stderr)"
            )
        last = port
    pytest.fail(f"freastal {kind} server never listened on {HOST}:{last}")


def _one_pid(url):
    # A new client per request: keep-alive would pin every request to the one
    # worker that accepted the first connection and tell us nothing about how
    # the kernel spreads connections.
    with httpx.Client(timeout=10.0) as client:
        r = client.get(f"{url}/pid", headers={"Connection": "close"})
    assert r.status_code == 200
    return int(r.text)


def _get_pids(url, n, concurrency=8):
    """Hit /pid n times on fresh connections; return the worker pids that answered.

    Concurrently, and that matters.  Issued one at a time, a request usually
    finds the worker that served the previous one already back in accept(), so
    the load lands very unevenly: measured over eight runs against three
    workers, sequential requests reached only two of them several times and
    gave the second worker as little as 1 of 60, while overlapping requests
    reached all three every time with the runner-up never below 10.  Asserting
    on a sequential distribution would be asserting on a coin flip.
    """
    with ThreadPoolExecutor(concurrency) as pool:
        return list(pool.map(lambda _: _one_pid(url), range(n)))


def _alive(pid):
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def _run_snippet(body, timeout=30):
    """Run a snippet in a fresh interpreter and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(body)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _run_module(body, timeout=30):
    """Run a snippet from a real file, not `python -c`.

    Necessary wherever the snippet starts workers: a spawned child re-imports
    __main__ *by path*, and `-c` code has no path, so the child cannot bring
    the module back. The snippet would then hang instead of reporting whatever
    it was written to report.
    """
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "snippet.py")
        with open(path, "w") as f:
            f.write(textwrap.dedent(body))
        return subprocess.run(
            [sys.executable, path],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )


# ---------------------------------------------------------------------------
# The grid
# ---------------------------------------------------------------------------

# reuse_port: None means "do not pass it at all", which is the case that
# matters -- bug 1 was only reachable through the default.
GRID = []
for _kind in ("wsgi", "asgi"):
    for _reuse in (None, True, False):
        for _workers in (None, 2):
            _kwargs = {}
            if _reuse is not None:
                _kwargs["reuse_port"] = _reuse
            if _workers is not None:
                _kwargs["workers"] = _workers
            _id = (
                f"{_kind}-reuse_port={'default' if _reuse is None else _reuse}"
                f"-workers={'default' if _workers is None else _workers}"
            )
            _marks = [requires_load_balancing] if _reuse is True else []
            GRID.append(pytest.param(_kind, _kwargs, id=_id, marks=_marks))


@pytest.mark.parametrize("kind,kwargs", GRID)
def test_grid_serves(kind, kwargs):
    """Every meaningful cell of the argument grid binds and answers a request."""
    with serving(kind, **kwargs) as url:
        r = httpx.get(f"{url}/pid", timeout=5.0)
        assert r.status_code == 200
        assert int(r.text) > 0


# ---------------------------------------------------------------------------
# Defaults.  This is the test that bug 1 needed and did not have.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["wsgi", "asgi"])
def test_defaults_bind_and_serve(kind):
    """Passing nothing but host and port must work.

    Bug 1: reuse_port defaulted to True, libuv refuses UV_TCP_REUSEPORT outside
    Linux/FreeBSD/DragonFly/Solaris, and so uv_tcp_bind failed at workers=1 on
    plaintext with no TLS in sight.  Every existing test passed reuse_port=False.
    """
    with serving(kind) as url:
        assert httpx.get(f"{url}/pid", timeout=5.0).status_code == 200


@pytest.mark.parametrize("entry", ["serve", "serve_asgi"])
def test_default_arguments_are_usable(entry):
    """The signature defaults themselves must be a runnable configuration.

    Guards against the defaults drifting back to a value that cannot bind: the
    grid above pins host and port, so it would not notice reuse_port defaulting
    to True again if serving() happened to be given it explicitly elsewhere.
    """
    sig = inspect.signature(getattr(freastal, entry))
    assert sig.parameters["workers"].default == 1
    assert sig.parameters["reuse_port"].default in (None, False), (
        "reuse_port must not default to True: it cannot bind on a platform "
        "without load-balancing SO_REUSEPORT, and it does nothing at workers=1"
    )


def test_bare_serve_with_no_arguments_at_all():
    """`freastal.serve(app)` -- host, port, workers and reuse_port all default.

    This is literally the README's smallest form.  Skipped rather than made
    flaky when something already holds the default port.
    """
    try:
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", 8000))
    except OSError as exc:
        pytest.skip(f"default port 8000 is not available here: {exc}")

    proc = _start_server("wsgi", {})
    try:
        assert _wait_until_serving(proc, 8000), (
            f"freastal.serve(app) with no arguments never listened "
            f"(exitcode={proc.exitcode})"
        )
        assert httpx.get("http://127.0.0.1:8000/pid", timeout=5.0).status_code == 200
    finally:
        _reap(proc)


# ---------------------------------------------------------------------------
# Multiple workers, for real
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["wsgi", "asgi"])
def test_multiple_workers_serve_and_share_the_load(kind):
    """workers=3 must start, answer, and answer from more than one process.

    Bug 2: the worker target was a closure, so Process.start() could not pickle
    it under spawn (macOS today, and forkserver on Linux from 3.14).  Nothing
    started a second worker, so nothing noticed.

    The pid in each response is the worker's, so this also proves the parent is
    not quietly serving everything itself.
    """
    workers = 3
    with serving(kind, workers=workers) as url:
        pids = _get_pids(url, 60)

    assert all(p > 0 for p in pids)
    distinct = set(pids)
    # Only that more than one worker served, never how evenly.  Kernel accept
    # balancing is not fair and does not promise to be; asserting a ratio here
    # would be asserting on scheduler noise.
    assert len(distinct) > 1, (
        f"all {len(pids)} requests were served by pid {distinct}: the workers "
        "started but only one of them is receiving connections -- which is what "
        "SO_REUSEPORT on macOS does, and why freastal does not use it there"
    )
    assert len(distinct) <= workers, (
        f"{len(distinct)} processes served but only {workers} workers were asked "
        f"for: {sorted(distinct)}"
    )


@pytest.mark.parametrize("kind", ["wsgi", "asgi"])
def test_workers_shut_down_with_the_parent(kind):
    """Stopping the parent must stop the workers, or the suite leaks servers."""
    with serving(kind, workers=2) as url:
        worker_pids = set(_get_pids(url, 20))
        assert worker_pids, "no worker answered"
        assert all(_alive(pid) for pid in worker_pids)

    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        survivors = {pid for pid in worker_pids if _alive(pid)}
        if not survivors:
            break
        time.sleep(0.05)
    else:
        pytest.fail(f"worker processes outlived their parent: {sorted(survivors)}")


# ---------------------------------------------------------------------------
# Failure paths: what the caller is told when the platform cannot comply
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    KERNEL_LOAD_BALANCES,
    reason="this kernel does load-balance SO_REUSEPORT, so the request is honoured",
)
@pytest.mark.parametrize("entry", ["serve", "serve_asgi"])
def test_reuse_port_true_is_refused_where_it_cannot_work(entry):
    """An explicit reuse_port=True the platform cannot honour must say so.

    Not silently ignored: on macOS SO_REUSEPORT binds happily and then hands
    every connection to one socket, so ignoring the request would produce a
    server that looks like it has N workers and behaves like it has one.  That
    is the failure mode issue #48 was hiding behind in the first place.
    """
    result = _run_snippet(f"""
        import freastal
        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"x"]
        async def aapp(scope, receive, send):
            pass
        entry = freastal.{entry}
        target = app if "{entry}" == "serve" else aapp
        entry(target, host="127.0.0.1", port=0, reuse_port=True)
    """)
    assert result.returncode != 0, f"expected a refusal, got:\n{result.stdout}"
    err = result.stderr
    assert "reuse_port" in err, err
    # The refusal has to name which of the two causes it is, because the fix
    # differs: a kernel that will not distribute connections (name the
    # platform) versus a libuv built without the flag at all (name the flag).
    # GitHub's ubuntu runners are the second case, which is why asserting only
    # the first passed locally and failed there.
    assert sys.platform in err or "REUSEPORT" in err, err


def test_reuse_port_resolution_is_explicit_about_what_it_chose():
    """The tri-state resolves the same way the bind path will behave.

    reuse_port=None is "auto": on wherever the kernel will honour it, off
    everywhere else.  An explicit False stays False everywhere.
    """
    assert freastal._resolve_reuse_port(False, workers=4) is False
    assert freastal._resolve_reuse_port(False, workers=1) is False

    # Auto keys off the capability, NOT off the worker count. Gating it on
    # workers>1 would read as harmless -- there is nothing to balance at one
    # worker -- but it turns reuse_port off at workers=1 on Linux, where
    # nothing was broken, and breaks a zero-downtime restart done by
    # overlapping two single-worker processes on the same port: the second
    # bind starts failing with EADDRINUSE at deploy time.
    assert freastal._resolve_reuse_port(None, workers=1) is KERNEL_LOAD_BALANCES
    assert freastal._resolve_reuse_port(None, workers=4) is KERNEL_LOAD_BALANCES

    if KERNEL_LOAD_BALANCES:
        assert freastal._resolve_reuse_port(True, workers=2) is True
    else:
        with pytest.raises(ValueError, match="reuse_port"):
            freastal._resolve_reuse_port(True, workers=2)


def test_kernel_capability_matches_libuv_platform_list():
    """freastal's notion of "this kernel load-balances" is the one libuv uses.

    Kept as a test because the two have to agree: the single-worker path still
    hands reuse_port to uv_tcp_bind, which fails with ENOTSUP anywhere libuv
    will not honour the flag, so a more optimistic answer here turns into a
    bind failure there.

    Note that freastal keeps no platform table of its own -- this asks the
    extension, which probes by attempting the bind. A table would restate a
    list libuv owns, go stale as libuv adds platforms, and still be wrong on
    old kernels: uv.h requires Linux 3.9+, DragonFlyBSD 3.6+, FreeBSD 12.0+,
    Solaris 11.4 or AIX 7.2.5+, so a platform *name* is not the capability.
    """
    assert freastal._kernel_load_balances_reuse_port() is KERNEL_LOAD_BALANCES


@pytest.mark.parametrize("kind", ["wsgi", "asgi"])
def test_per_worker_reuse_port_sockets_bind_and_serve(kind):
    """The SO_REUSEPORT branch of _run_workers: N listeners, one per worker.

    On a load-balancing kernel this is the default shape at workers>1, and this
    machine is not one, so the branch would otherwise never execute here.  See
    _serve_target_forcing_reuse_port for what this does and does not establish
    -- notably it asserts nothing about distribution, because macOS pins the
    whole group to one socket.
    """
    with serving(
        kind, _target=_serve_target_forcing_reuse_port, workers=2, reuse_port=True
    ) as url:
        pids = _get_pids(url, 10)
    assert all(p > 0 for p in pids)


@pytest.mark.parametrize("kind", ["wsgi", "asgi"])
def test_bind_failure_is_raised_by_the_parent(kind):
    """A port already in use must fail once, out of serve(), not N times inside workers.

    The parent binds before starting anything, so the caller gets the OSError
    with a traceback instead of N workers dying somewhere their stderr may not
    be read.
    """
    holder = socket.socket()
    holder.bind((HOST, 0))
    holder.listen(8)
    port = holder.getsockname()[1]
    try:
        entry = "serve" if kind == "wsgi" else "serve_asgi"
        result = _run_snippet(f"""
            import freastal
            def app(environ, start_response):
                start_response("200 OK", [("Content-Type", "text/plain")])
                return [b"x"]
            async def aapp(scope, receive, send):
                pass
            target = app if "{entry}" == "serve" else aapp
            freastal.{entry}(target, host="{HOST}", port={port}, workers=2)
        """)
    finally:
        holder.close()

    assert result.returncode != 0, f"expected a bind failure, got:\n{result.stdout}"
    # Raised from the parent's own bind, not from a worker: no worker got far
    # enough to announce itself.
    assert "OSError" in result.stderr, result.stderr
    assert "starting" not in result.stdout, result.stdout


def test_parent_does_not_report_success_when_its_workers_die():
    """A worker that cannot start must not look like a running server.

    The parent binds, so a worker no longer fails at bind -- but it can still
    die at startup (bad TLS material, an app the child cannot use), and before
    this the parent simply joined the corpses and returned None, which reads
    exactly like a clean shutdown.
    """
    port = _free_port()
    result = _run_snippet(f"""
        import freastal
        freastal.serve(None, host="{HOST}", port={port}, workers=2)
    """)
    assert result.returncode != 0, f"serve() returned success:\n{result.stdout}"
    assert "RuntimeError" in result.stderr, result.stderr
    assert "worker(s) exited" in result.stderr, result.stderr


def test_app_that_cannot_reach_the_worker_is_reported():
    """workers>1 under spawn needs an importable app, and says so when it is not.

    An app defined in __main__ (or a lambda, or a closure) cannot be handed to
    a spawned worker.  That is inherent to the start method rather than
    something freastal can paper over, so the requirement is documented -- but
    the failure still has to be visible rather than a server that silently
    never serves.
    """
    if mp.get_start_method() == "fork":
        pytest.skip(
            "fork does not pickle the target, so an unpicklable app is not an "
            "error there; this is a spawn/forkserver requirement"
        )
    # A real file, not `python -c`: a spawned child re-imports __main__ by
    # path, and there is no path for -c code, so the snippet would hang rather
    # than report the very failure under test.
    port = _free_port()
    result = _run_module(f"""
        import freastal
        app = lambda environ, start_response: []
        if __name__ == "__main__":
            freastal.serve(app, host="{HOST}", port={port}, workers=2)
    """)
    assert result.returncode != 0
    assert "pickle" in result.stderr.lower() or "RuntimeError" in result.stderr, (
        result.stderr
    )
