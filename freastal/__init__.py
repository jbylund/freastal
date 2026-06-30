"""freastal – libuv + picohttpparser WSGI/ASGI server."""

import asyncio
import os
import signal
import sys
import multiprocessing
import time

from ._freastal import (
    serve as _serve_single,
    serve_asgi as _serve_asgi_single,
    __version__,
)

__all__ = ["serve", "serve_asgi", "__version__"]


def serve(
    app,
    host="0.0.0.0",
    port=8000,
    workers=1,
    reuse_port=True,
    certfile=None,
    keyfile=None,
):
    """Start freastal.

    With workers=1 (default) runs in-process.
    With workers>1 forks worker processes, each binding with SO_REUSEPORT
    so the kernel load-balances connections across them.
    Pass certfile and keyfile (PEM paths) to enable TLS 1.3 (requires picotls).
    """
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

    processes = []

    def _worker(worker_id):
        print(f"[freastal] worker {worker_id} pid={os.getpid()} starting", flush=True)
        try:
            _serve_single(
                app,
                host=host,
                port=port,
                reuse_port=True,
                certfile=certfile,
                keyfile=keyfile,
            )
        except KeyboardInterrupt:
            pass

    def _shutdown(sig, frame):
        for p in processes:
            p.terminate()
        for p in processes:
            p.join(timeout=5)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    for i in range(workers):
        p = multiprocessing.Process(target=_worker, args=(i + 1,), daemon=True)
        p.start()
        processes.append(p)

    for p in processes:
        p.join()


def serve_asgi(app, host="0.0.0.0", port=8000, workers=1, reuse_port=True):
    """Start freastal in ASGI mode.

    With workers=1 runs in-process.
    With workers>1 forks worker processes using SO_REUSEPORT.
    Each worker creates its own asyncio event loop.
    """

    def _run_single():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _serve_asgi_single(app, loop, host=host, port=port, reuse_port=reuse_port)

    if workers <= 1:
        _run_single()
        return

    processes = []

    def _worker(worker_id):
        print(
            f"[freastal] ASGI worker {worker_id} pid={os.getpid()} starting", flush=True
        )
        try:
            _run_single()
        except KeyboardInterrupt:
            pass

    def _shutdown(sig, frame):
        for p in processes:
            p.terminate()
        for p in processes:
            p.join(timeout=5)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    for i in range(workers):
        p = multiprocessing.Process(target=_worker, args=(i + 1,), daemon=True)
        p.start()
        processes.append(p)
        time.sleep(0.05)

    for p in processes:
        p.join()
