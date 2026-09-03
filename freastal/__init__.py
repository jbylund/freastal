"""freastal – libuv + picohttpparser WSGI/ASGI server."""

import asyncio
import multiprocessing
import os
import signal
import socket
import sys

from . import _freastal
from ._freastal import __version__
from ._freastal import has_tls as _has_tls_int
from ._freastal import serve as _serve_single
from ._freastal import serve_asgi as _serve_asgi_single

#: True when this build can serve TLS.  A build without OpenSSL headers
#: cannot honour certfile/keyfile and now refuses them rather than falling
#: back to plaintext; this is how a caller checks before asking.
has_tls = bool(_has_tls_int)

__all__ = ["__version__", "serve", "serve_asgi"]


# Kernels whose SO_REUSEPORT spreads incoming connections across the sockets of
# the group.  This is libuv's own list for UV_TCP_REUSEPORT, and it has to stay
# in step with it: the single-worker path still asks libuv to set the flag, and
# libuv returns ENOTSUP anywhere outside this list.
#
# It is a platform property, not something a runtime probe can answer.  macOS
# accepts SO_REUSEPORT on a TCP listener and binds without complaint, then
# delivers every connection to one socket in the group -- measured at 60/60 to
# a single listener out of three.  A probe that only checked setsockopt+bind
# would call that "supported" and be wrong in exactly the way that matters.
def _kernel_load_balances_reuse_port():
    """True if libuv on THIS machine will honour UV_TCP_REUSEPORT.

    Asks the extension, which probes by attempting the bind. Deliberately not a
    platform table and not a setsockopt check:

    * A table restates a list libuv owns and goes stale as libuv adds
      platforms. It is also wrong on old kernels regardless -- uv.h says the
      flag needs "Linux 3.9+, DragonFlyBSD 3.6+, FreeBSD 12.0+, Solaris 11.4,
      and AIX 7.2.5+ for now", so a platform *name* is not the capability.
    * A setsockopt probe is worse than useless. macOS *has* SO_REUSEPORT:
      setsockopt succeeds, a second bind to the same port succeeds, and then
      the last binder takes every connection while the first gets none --
      measured at 40 out of 40. That is BSD rebind semantics, not Linux's
      connection-distributing SO_REUSEPORT, and a probe that answers "does the
      option exist" hands back a server where one worker serves everything.
    * setup.py can only say whether the enum was in the uv.h it compiled
      against, which is fixed into a wheel that then runs on other machines.

    libuv's refusal tracks the distinction that matters, so ask libuv.
    """
    return bool(_freastal.reuse_port_supported())


def _resolve_reuse_port(reuse_port, workers):
    """Turn the tri-state reuse_port into the bool the bind path will use.

    None means "auto": on wherever the kernel will honour it, off everywhere
    else.  It used to default to True, which meant a bare freastal.serve(app)
    could not bind at all on macOS (#49).

    Auto keys off the capability, not off the worker count.  Turning it off at
    workers=1 would be a behaviour change on Linux -- the one platform where
    nothing was broken -- and would break a zero-downtime restart done by
    overlapping two single-worker processes on the same port, which relies on
    today's default and would start failing with EADDRINUSE at deploy time.

    True on a platform or build that cannot honour it raises.  Ignoring it would
    hand back a server that looks like it has N workers and behaves like it has
    one, and that silence is why the broken default survived this long.
    """
    if reuse_port is None:
        return _kernel_load_balances_reuse_port()

    if not reuse_port:
        return False

    if not _kernel_load_balances_reuse_port():
        raise ValueError(
            f"reuse_port=True cannot be honoured on {sys.platform}: SO_REUSEPORT "
            "is accepted here but does not load-balance TCP listeners -- every "
            "connection is delivered to one socket in the group, so the other "
            "workers would sit idle.  libuv refuses UV_TCP_REUSEPORT here for "
            "the same reason.  Leave reuse_port unset (or pass False) and "
            "freastal shares one bound listening socket across the workers "
            "instead, which does load-balance."
        )

    return True


def _make_listener(host, port, reuse_port):
    """Bind a listening socket for the workers to serve on.

    Bound but deliberately not listen()ed: libuv calls listen() itself with its
    own backlog when the socket reaches uv_tcp_open/uv_listen.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if reuse_port:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind((host, port))
    except OSError:
        sock.close()
        raise
    return sock


def _wsgi_worker(worker_id, sock, app, host, port, certfile, keyfile):
    """Worker entry point, at module level so multiprocessing can pickle it.

    It used to be a closure inside serve(), which the fork start method never
    had to pickle.  spawn does, and spawn is the default on macOS today and
    what forkserver (Linux's default from 3.14) does too, so Process.start()
    died with "Can't pickle local object" before a worker ever ran.

    `app` travels as an argument for the same reason: under spawn the child
    re-imports rather than inheriting, so the app has to be picklable -- in
    practice a module-level callable.
    """
    # A worker has to die when the supervisor terminates it.  Under fork it
    # inherits the supervisor's Python-level SIGTERM handler, and a Python
    # handler cannot run while server_run() is inside uv_run with the GIL
    # released: an idle worker would not notice SIGTERM until its next request,
    # the supervisor's join() would time out, and the worker would be
    # reparented to init and left running -- 54 of them after one test run.
    # Restoring the default disposition kills the process in the kernel.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.default_int_handler)

    print(f"[freastal] worker {worker_id} pid={os.getpid()} starting", flush=True)
    try:
        _serve_single(
            app,
            host=host,
            port=port,
            certfile=certfile,
            keyfile=keyfile,
            fd=sock.fileno(),
        )
    except KeyboardInterrupt:
        pass


def _asgi_worker(worker_id, sock, app, host, port, certfile, keyfile):
    """As _wsgi_worker, with a fresh event loop per worker."""
    # A worker has to die when the supervisor terminates it.  Under fork it
    # inherits the supervisor's Python-level SIGTERM handler, and a Python
    # handler cannot run while server_run() is inside uv_run with the GIL
    # released: an idle worker would not notice SIGTERM until its next request,
    # the supervisor's join() would time out, and the worker would be
    # reparented to init and left running -- 54 of them after one test run.
    # Restoring the default disposition kills the process in the kernel.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.default_int_handler)

    print(f"[freastal] ASGI worker {worker_id} pid={os.getpid()} starting", flush=True)
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _serve_asgi_single(
            app,
            loop,
            host=host,
            port=port,
            certfile=certfile,
            keyfile=keyfile,
            fd=sock.fileno(),
        )
    except KeyboardInterrupt:
        pass


def _run_workers(worker, app, host, port, workers, reuse_port, certfile, keyfile):
    """Bind here, then run `workers` copies of `worker` on the result.

    Two shapes, one code path:

      * reuse_port -- one socket per worker, all with SO_REUSEPORT, so the
        kernel gives each worker its own accept queue.
      * otherwise -- a single socket shared by every worker, which is the only
        model that works where SO_REUSEPORT does not load-balance, and needs no
        special kernel support anywhere.

    Binding in the parent rather than in each worker means an EADDRINUSE or a
    permission error is raised once, from serve(), with a traceback the caller
    can see -- instead of N times inside workers whose stderr may be going
    somewhere else entirely.
    """
    listeners = []
    try:
        for _ in range(workers if reuse_port else 1):
            listeners.append(_make_listener(host, port, reuse_port))
            # port=0 asks for an ephemeral port, which would hand every
            # SO_REUSEPORT listener a *different* port.  Pin the one the first
            # bind chose so the rest join the same group.
            port = listeners[0].getsockname()[1]
    except OSError:
        for sock in listeners:
            sock.close()
        raise

    processes = []

    def _shutdown(sig, frame):
        for p in processes:
            p.terminate()
        for p in processes:
            p.join(timeout=5)
        sys.exit(0)

    # Pre-existing, and hit for real by anything that calls serve() off the
    # main thread: signal.signal raises ValueError there.  Terminating the
    # workers on SIGINT is a convenience, so failing to arm it must not stop
    # the server from starting -- the workers are daemon=True and die with the
    # parent regardless.
    try:
        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)
    except ValueError:
        pass

    for i in range(workers):
        p = multiprocessing.Process(
            target=worker,
            args=(
                i + 1,
                listeners[i % len(listeners)],
                app,
                host,
                port,
                certfile,
                keyfile,
            ),
            daemon=True,
        )
        p.start()
        processes.append(p)

    # `listeners` stays referenced until every worker has exited: under spawn
    # the socket is handed over through multiprocessing's resource sharer,
    # which serves the descriptor from a thread in *this* process when the
    # child asks for it.  Closing early would race that handover.
    for p in processes:
        p.join()

    failed = [p.exitcode for p in processes if p.exitcode]
    if failed:
        raise RuntimeError(
            f"freastal: {len(failed)} of {workers} worker(s) exited with {failed}"
        )


def serve(
    app,
    host="0.0.0.0",
    port=8000,
    workers=1,
    reuse_port=None,
    certfile=None,
    keyfile=None,
):
    """Start freastal.

    With workers=1 (default) runs in-process.
    With workers>1 starts worker processes that share the listening socket the
    parent bound, so the kernel spreads connections across them.  The app must
    be picklable (a module-level callable) because the spawn and forkserver
    start methods re-import the child rather than inheriting it.

    reuse_port is a tri-state.  None (default) enables SO_REUSEPORT only where
    it does something: more than one worker, on a kernel that load-balances the
    group.  True demands it and raises where it cannot be honoured.  False
    never uses it.

    Pass certfile and keyfile (PEM paths) to enable TLS 1.3 (requires picotls).
    """
    reuse_port = _resolve_reuse_port(reuse_port, workers)

    if workers <= 1:
        _serve_single(
            app,
            host=host,
            port=port,
            reuse_port=reuse_port,
            certfile=certfile,
            keyfile=keyfile,
        )
        return

    _run_workers(_wsgi_worker, app, host, port, workers, reuse_port, certfile, keyfile)


def serve_asgi(
    app,
    host="0.0.0.0",
    port=8000,
    workers=1,
    reuse_port=None,
    certfile=None,
    keyfile=None,
):
    """Start freastal in ASGI mode.

    With workers=1 runs in-process.
    With workers>1 starts worker processes over a shared listening socket, each
    with its own asyncio event loop.  See serve() for the reuse_port tri-state
    and the picklability requirement on app.

    Pass certfile and keyfile (PEM paths) to enable TLS 1.3 (requires picotls).
    """
    reuse_port = _resolve_reuse_port(reuse_port, workers)

    if workers <= 1:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _serve_asgi_single(
            app,
            loop,
            host=host,
            port=port,
            reuse_port=reuse_port,
            certfile=certfile,
            keyfile=keyfile,
        )
        return

    _run_workers(_asgi_worker, app, host, port, workers, reuse_port, certfile, keyfile)
