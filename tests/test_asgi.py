"""ASGI-specific tests."""

import json

import httpx


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
