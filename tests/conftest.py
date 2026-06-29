import multiprocessing
import socket
import time

import pytest

import freastal


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host, port, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Server did not start on {host}:{port}")


# ---------------------------------------------------------------------------
# WSGI app
# ---------------------------------------------------------------------------

def _wsgi_app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")

    if path == "/hello":
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"hello"]

    if path == "/echo" and method == "POST":
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(length)
        start_response("200 OK", [("Content-Type", "application/octet-stream")])
        return [body]

    if path == "/header":
        value = environ.get("HTTP_X_TEST", "")
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [value.encode()]

    if path == "/query":
        qs = environ.get("QUERY_STRING", "")
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [qs.encode()]

    if path == "/remote-addr":
        addr = environ.get("REMOTE_ADDR", "")
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [addr.encode()]

    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"not found"]


def _run_wsgi(port):
    freastal.serve(_wsgi_app, host="127.0.0.1", port=port, workers=1, reuse_port=False)


@pytest.fixture(scope="session")
def wsgi_url():
    port = _free_port()
    p = multiprocessing.Process(target=_run_wsgi, args=(port,), daemon=True)
    p.start()
    _wait_for_port("127.0.0.1", port)
    yield f"http://127.0.0.1:{port}"
    p.terminate()
    p.join(timeout=3)


# ---------------------------------------------------------------------------
# ASGI app
# ---------------------------------------------------------------------------

async def _asgi_app(scope, receive, send):
    if scope["type"] != "http":
        return

    path = scope.get("path", "/")
    method = scope.get("method", "GET")

    if path == "/hello":
        await send({"type": "http.response.start", "status": 200,
                    "headers": [[b"content-type", b"text/plain"]]})
        await send({"type": "http.response.body", "body": b"hello"})
        return

    if path == "/echo" and method == "POST":
        event = await receive()
        body = event.get("body", b"")
        await send({"type": "http.response.start", "status": 200,
                    "headers": [[b"content-type", b"application/octet-stream"]]})
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/header":
        hdrs = dict(scope.get("headers", []))
        value = hdrs.get(b"x-test", b"").decode()
        await send({"type": "http.response.start", "status": 200,
                    "headers": [[b"content-type", b"text/plain"]]})
        await send({"type": "http.response.body", "body": value.encode()})
        return

    if path == "/query":
        qs = scope.get("query_string", b"").decode()
        await send({"type": "http.response.start", "status": 200,
                    "headers": [[b"content-type", b"text/plain"]]})
        await send({"type": "http.response.body", "body": qs.encode()})
        return

    if path == "/remote-addr":
        client = scope.get("client")
        addr = client[0] if client else ""
        await send({"type": "http.response.start", "status": 200,
                    "headers": [[b"content-type", b"text/plain"]]})
        await send({"type": "http.response.body", "body": addr.encode()})
        return

    if path == "/scope":
        import json
        data = json.dumps({
            "method": scope.get("method"),
            "path": scope.get("path"),
            "query_string": scope.get("query_string", b"").decode(),
        }).encode()
        await send({"type": "http.response.start", "status": 200,
                    "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body", "body": data})
        return

    await send({"type": "http.response.start", "status": 404,
                "headers": [[b"content-type", b"text/plain"]]})
    await send({"type": "http.response.body", "body": b"not found"})


def _run_asgi(port):
    freastal.serve_asgi(_asgi_app, host="127.0.0.1", port=port, workers=1, reuse_port=False)


@pytest.fixture(scope="session")
def asgi_url():
    port = _free_port()
    p = multiprocessing.Process(target=_run_asgi, args=(port,), daemon=True)
    p.start()
    _wait_for_port("127.0.0.1", port)
    yield f"http://127.0.0.1:{port}"
    p.terminate()
    p.join(timeout=3)


# ---------------------------------------------------------------------------
# Combined fixture — parametrizes any test that uses server_url
# ---------------------------------------------------------------------------

@pytest.fixture(params=["wsgi_url", "asgi_url"])
def server_url(request):
    return request.getfixturevalue(request.param)
