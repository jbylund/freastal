"""ASGI-specific tests."""

import json
import socket
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


SCOPE_KEYS = sorted(
    [
        "type",
        "asgi",
        "http_version",
        "method",
        "scheme",
        "root_path",
        "path",
        "raw_path",
        "query_string",
        "client",
        "server",
        "headers",
    ]
)


def _read_all(sock):
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _bodies(raw):
    """Split a stream of pipelined HTTP/1.x responses into their bodies."""
    out = []
    while raw:
        head, _, rest = raw.partition(b"\r\n\r\n")
        length = int(
            next(
                line.split(b":", 1)[1]
                for line in head.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
        )
        out.append(rest[:length])
        raw = rest[length:]
    return out


def test_scope_is_complete_and_isolated_per_request(asgi_url):
    """Every documented key is present, and an app that rewrites the scope
    must not be able to leak its edits into the next request on the same
    connection."""
    with httpx.Client(base_url=asgi_url) as client:
        for _ in range(3):
            d = json.loads(client.get("/scope-all?a=1&b=2").content)
            assert d["keys"] == SCOPE_KEYS
            # dict(scope) reads C-level storage, so it must see the same keys.
            assert d["dict_copy_keys"] == SCOPE_KEYS
            assert d["is_dict"] is True
            assert d["type"] == "http"
            assert d["asgi"] == {"version": "3.0"}
            assert d["http_version"] == "1.1"
            assert d["method"] == "GET"
            assert d["scheme"] == "http"
            assert d["root_path"] == ""
            assert d["path"] == "/scope-all"
            assert d["raw_path"] == "/scope-all"
            assert d["query_string"] == "a=1&b=2"
            assert d["client"][0] == "127.0.0.1"
            assert isinstance(d["client"][1], int) and d["client"][1] > 0
            assert d["server"] == ["127.0.0.1", int(asgi_url.rsplit(":", 1)[1])]
            assert "host" in d["header_names"]


def test_query_string_resets_between_requests_on_one_connection(asgi_url):
    """A request with no '?' must report b"", even right after one that had a
    query string on the same connection."""
    with httpx.Client(base_url=asgi_url) as client:
        assert json.loads(client.get("/scope-all?a=1").content)["query_string"] == "a=1"
        assert json.loads(client.get("/scope-all").content)["query_string"] == ""
        assert json.loads(client.get("/scope-all?z=9").content)["query_string"] == "z=9"


def test_http_10_request_reports_http_version_1_0(asgi_url):
    host, port = asgi_url.removeprefix("http://").rsplit(":", 1)
    with socket.create_connection((host, int(port))) as sock:
        sock.sendall(b"GET /scope-all HTTP/1.0\r\nHost: t\r\n\r\n")
        d = json.loads(_bodies(_read_all(sock))[0])
    assert d["http_version"] == "1.0"
    assert d["keys"] == SCOPE_KEYS


def test_pipelined_requests_get_independent_scopes(asgi_url):
    """Two requests in one segment are dispatched back to back; each must get
    its own scope."""
    host, port = asgi_url.removeprefix("http://").rsplit(":", 1)
    with socket.create_connection((host, int(port))) as sock:
        sock.sendall(
            b"GET /scope-all?first=1 HTTP/1.1\r\nHost: t\r\n\r\n"
            b"GET /scope-all HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
        )
        first, second = (json.loads(b) for b in _bodies(_read_all(sock))[:2])
    assert first["query_string"] == "first=1"
    assert second["query_string"] == ""
    assert first["keys"] == second["keys"] == SCOPE_KEYS
    assert first["client"] == second["client"]
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
