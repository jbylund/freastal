"""A timer armed for a handle that is cancelled before it fires must not hang.

freastal arms a uv_timer_t for the earliest entry on loop._scheduled and, when
it fires, calls loop._run_once().  If that entry was cancelled in the meantime
(asyncio.wait_for, asyncio.timeout and psycopg's connection pool all do this
constantly), _run_once() discards it, finds nothing left to wait for, and used
to block in select() with no timeout -- on the thread libuv runs on, so the
whole server stopped answering.  Reported as an AsyncConnectionPool hang.
"""

import asyncio
import multiprocessing
import socket
import time

import pytest
from conftest import _free_port, _wait_for_port

import freastal


async def _app(scope, receive, send):
    if scope.get("path") == "/arm":
        # Suspends (so freastal arms its timer), and leaves a cancelled
        # 5-second TimerHandle behind on loop._scheduled.
        await asyncio.wait_for(asyncio.sleep(0.001), timeout=0.05)
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


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
    with socket.create_connection(addr, timeout=3) as s:
        s.sendall(f"GET {target} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".encode())
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks)


def test_server_survives_a_timer_cancelled_before_it_fires(addr):
    assert _fetch(addr, "/arm").endswith(b"ok")
    time.sleep(0.3)  # well past the cancelled handle's deadline
    assert _fetch(addr, "/").endswith(b"ok")
    assert _fetch(addr, "/arm").endswith(b"ok")
