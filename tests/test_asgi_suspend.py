"""ASGI apps that suspend must be resumed by the libuv <-> asyncio bridge.

uv_check_t fires once per libuv iteration, and libuv blocks in its poll phase
whenever no socket is ready. Without something keeping the loop iterating,
asyncio stops being stepped and a suspended task hangs until unrelated traffic
happens to wake the loop.
"""

import time

import httpx
import pytest


@pytest.mark.parametrize("n", [1, 2, 3, 10, 50])
def test_repeated_suspension_completes(asgi_url, n):
    r = httpx.get(f"{asgi_url}/await-chain/{n}", timeout=10)
    assert r.status_code == 200
    assert r.content == b"chained"


def test_sleep_resumes_and_honours_the_delay(asgi_url):
    start = time.perf_counter()
    r = httpx.get(f"{asgi_url}/sleep/0.25", timeout=10)
    elapsed = time.perf_counter() - start
    assert r.status_code == 200
    assert r.content == b"slept"
    assert elapsed >= 0.24, f"returned early after {elapsed:.3f}s"
    assert elapsed < 3.0, f"took {elapsed:.3f}s; loop is not waking promptly"


def test_zero_sleep_resumes(asgi_url):
    r = httpx.get(f"{asgi_url}/sleep/0", timeout=10)
    assert r.content == b"slept"


def test_socket_io_resumes(asgi_url):
    r = httpx.get(f"{asgi_url}/await-io", timeout=10)
    assert r.content == b"pong"


def test_suspending_requests_do_not_need_unrelated_traffic(asgi_url):
    """A single in-flight suspending request, with nothing else touching the
    server, is exactly the case that used to deadlock."""
    with httpx.Client(base_url=asgi_url, timeout=10) as client:
        for _ in range(5):
            assert client.get("/await-chain/20").content == b"chained"


def test_keep_alive_mixes_sync_and_suspending_requests(asgi_url):
    with httpx.Client(base_url=asgi_url, timeout=10) as client:
        for _ in range(3):
            assert client.get("/hello").content == b"hello"
            assert client.get("/await-chain/5").content == b"chained"
            assert client.get("/sleep/0.01").content == b"slept"
            assert client.get("/await-io").content == b"pong"
