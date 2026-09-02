"""ASGI-specific tests."""

import json
import sys

import httpx
import pytest


def test_scope_fields(asgi_url):
    """Verify freastal populates the ASGI scope correctly."""
    r = httpx.get(f"{asgi_url}/scope?x=1")
    assert r.status_code == 200
    data = json.loads(r.content)
    assert data["method"] == "GET"
    assert data["path"] == "/scope"
    assert data["query_string"] == "x=1"


def test_running_loop_is_current_inside_the_app(asgi_url):
    """The eager path runs the app outside _run_once(); the loop must still be current."""
    r = httpx.get(f"{asgi_url}/running-loop")
    assert r.status_code == 200
    assert r.content.endswith(b"EventLoop")


def test_app_that_awaits_a_future_still_responds(asgi_url):
    r = httpx.get(f"{asgi_url}/await-soon")
    assert r.status_code == 200
    assert r.content == b"resumed"


def test_app_that_awaits_real_socket_io_still_responds(asgi_url):
    r = httpx.get(f"{asgi_url}/await-io")
    assert r.status_code == 200
    assert r.content == b"pong"


def test_app_exception_returns_500(asgi_url):
    r = httpx.get(f"{asgi_url}/boom")
    assert r.status_code == 500


def test_keep_alive_survives_a_mix_of_paths(asgi_url):
    """Sync and suspending requests must not corrupt a reused connection."""
    with httpx.Client(base_url=asgi_url) as client:
        for _ in range(3):
            assert client.get("/hello").content == b"hello"
            assert client.get("/await-soon").content == b"resumed"
            assert client.get("/await-io").content == b"pong"


def test_contextvars_do_not_leak_between_requests(asgi_url):
    """A ContextVar set while handling one request must not reach the next.

    The eager path runs the app in the server's own context unless something
    gives it one of its own, and then every later request on that worker
    inherits whatever the last one set - trace ids, tenant ids, logging
    context bleeding between callers.
    """
    with httpx.Client(base_url=asgi_url) as client:
        assert client.get("/ctxvar").content == b"clean"
        assert client.get("/ctxvar").content == b"clean", "leaked into next request"


def test_current_task_is_set_inside_the_app(asgi_url):
    assert httpx.get(f"{asgi_url}/current-task").content == b"task"


def test_wait_for_works_inside_the_app(asgi_url):
    r = httpx.get(f"{asgi_url}/wait-for", timeout=10)
    assert r.status_code == 200
    assert r.content == b"waited"


@pytest.mark.skipif(sys.version_info < (3, 11), reason="asyncio.timeout is 3.11+")
def test_expiring_timeout_raises_inside_the_app(asgi_url):
    r = httpx.get(f"{asgi_url}/timeout-expires", timeout=10)
    assert r.status_code == 200
    assert r.content == b"expired"
