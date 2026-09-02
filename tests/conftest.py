import contextvars
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

    if path == "/headers":
        # "name=value" per line, names normalised back to their wire form so
        # the same assertions work against the ASGI app.
        lines = sorted(
            f"{k[5:].lower().replace('_', '-')}={v}"
            for k, v in environ.items()
            if k.startswith("HTTP_")
        )
        start_response("200 OK", [("Content-Type", "text/plain")])
        return ["\n".join(lines).encode("latin-1")]

    if path == "/query":
        qs = environ.get("QUERY_STRING", "")
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [qs.encode()]

    if path == "/remote-addr":
        addr = environ.get("REMOTE_ADDR", "")
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [addr.encode()]

    if path.startswith("/echo-path"):
        # PEP 3333 environ values are latin-1; hand the raw bytes back so a
        # test can assert on them exactly.
        start_response("200 OK", [("Content-Type", "application/octet-stream")])
        return [path.encode("latin-1")]

    if path == "/echo-header":
        start_response("200 OK", [("Content-Type", "application/octet-stream")])
        return [environ.get("HTTP_X_TEST", "").encode("latin-1")]

    if path == "/echo-query":
        start_response("200 OK", [("Content-Type", "application/octet-stream")])
        return [environ.get("QUERY_STRING", "").encode("latin-1")]

    if path == "/echo-ctype":
        start_response("200 OK", [("Content-Type", "application/octet-stream")])
        return [environ.get("CONTENT_TYPE", "").encode("latin-1")]

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


# Request-scoped state: a set() in one request must not be visible in the
# next one this worker handles.
_TENANT = contextvars.ContextVar("tenant", default="clean")


async def _asgi_app(scope, receive, send):
    if scope["type"] != "http":
        return

    path = scope.get("path", "/")
    method = scope.get("method", "GET")

    if path == "/hello":
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": b"hello"})
        return

    if path == "/echo" and method == "POST":
        event = await receive()
        body = event.get("body", b"")
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"application/octet-stream"]],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/header":
        hdrs = dict(scope.get("headers", []))
        value = hdrs.get(b"x-test", b"").decode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": value.encode()})
        return

    if path == "/headers":
        lines = sorted(
            f"{n.decode('latin-1')}={v.decode('latin-1')}"
            for n, v in scope.get("headers", [])
        )
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send(
            {"type": "http.response.body", "body": "\n".join(lines).encode("latin-1")}
        )
        return

    if path == "/query":
        qs = scope.get("query_string", b"").decode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": qs.encode()})
        return

    if path == "/remote-addr":
        client = scope.get("client")
        addr = client[0] if client else ""
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": addr.encode()})
        return

    if path.startswith("/await-chain/"):
        # Suspends once per iteration, so it only completes if libuv keeps
        # iterating while asyncio still has queued callbacks.
        import asyncio

        loop = asyncio.get_running_loop()
        for _ in range(int(path.rsplit("/", 1)[1])):
            fut = loop.create_future()
            loop.call_soon(fut.set_result, None)
            await fut
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": b"chained"})
        return

    if path.startswith("/sleep/"):
        # Only completes if libuv's poll wakes for asyncio's timer deadline.
        import asyncio

        delay = float(path.rsplit("/", 1)[1])
        await asyncio.sleep(delay)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": b"slept"})
        return

    if path == "/await-io":
        # Suspends on real socket readiness, resumed via asyncio's selector.
        import asyncio
        import socket as _socket

        loop = asyncio.get_running_loop()
        a, b = _socket.socketpair()
        a.setblocking(False)
        b.setblocking(False)
        try:
            loop.call_later(0.01, b.send, b"pong")
            data = await loop.sock_recv(a, 4)
        finally:
            a.close()
            b.close()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": data})
        return

    if path == "/running-loop":
        # The eager fast path runs the app outside loop._run_once(), so this
        # asserts freastal still makes the loop current for the call.
        import asyncio

        name = type(asyncio.get_running_loop()).__name__.encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": name})
        return

    if path == "/await-soon":
        # Suspends once, on a future resolved from the loop's ready queue.
        import asyncio

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        loop.call_soon(fut.set_result, b"resumed")
        body = await fut
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/ctxvar":
        # Reports what it inherited, then dirties the var.  Two requests in a
        # row must both report "clean".
        inherited = _TENANT.get()
        _TENANT.set("dirty")
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": inherited.encode()})
        return

    if path == "/current-task":
        # The eager path runs the app with no real Task; asyncio must still
        # have a current task to report.
        import asyncio

        body = b"task" if asyncio.current_task() is not None else b"none"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/wait-for":
        # On 3.12+ wait_for is asyncio.timeout underneath, which refuses to
        # run without a current task.
        import asyncio

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        loop.call_soon(fut.set_result, b"waited")
        body = await asyncio.wait_for(fut, 5)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/timeout-expires":
        # asyncio.timeout captures current_task() on the eager step but only
        # cancels it from a later loop callback (3.11+ only).
        import asyncio

        try:
            async with asyncio.timeout(0.05):
                await asyncio.get_running_loop().create_future()
        except TimeoutError:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [[b"content-type", b"text/plain"]],
                }
            )
            await send({"type": "http.response.body", "body": b"expired"})
        return

    if path == "/boom":
        raise RuntimeError("app failure")

    if path == "/scope-all":
        import json

        # Snapshot the whole scope, then vandalise it the way Starlette and
        # FastAPI do.  Hitting this repeatedly on one connection proves the
        # scope is a fresh dict per request rather than a shared or recycled
        # one: the snapshot must come back identical every time.
        snapshot = {
            "keys": sorted(scope),
            "dict_copy_keys": sorted(dict(scope)),
            "is_dict": type(scope) is dict,
            "type": scope.get("type"),
            "asgi": scope.get("asgi"),
            "http_version": scope.get("http_version"),
            "method": scope.get("method"),
            "scheme": scope.get("scheme"),
            "root_path": scope.get("root_path"),
            "path": scope.get("path"),
            "raw_path": scope.get("raw_path", b"").decode(),
            "query_string": scope.get("query_string", b"").decode(),
            "client": list(scope.get("client") or []),
            "server": list(scope.get("server") or []),
            "header_names": sorted(n.decode() for n, _ in scope.get("headers", [])),
        }
        scope["app"] = object()
        scope["router"] = object()
        scope["path_params"] = {}
        scope["endpoint"] = object()
        scope["route"] = object()
        scope["state"] = {}
        scope["root_path"] = "/mounted"
        scope["path"] = "/rewritten"

        data = json.dumps(snapshot).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"application/json"]],
            }
        )
        await send({"type": "http.response.body", "body": data})
        return

    if path == "/scope":
        import json

        data = json.dumps(
            {
                "method": scope.get("method"),
                "path": scope.get("path"),
                "query_string": scope.get("query_string", b"").decode(),
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"application/json"]],
            }
        )
        await send({"type": "http.response.body", "body": data})
        return

    await send(
        {
            "type": "http.response.start",
            "status": 404,
            "headers": [[b"content-type", b"text/plain"]],
        }
    )
    await send({"type": "http.response.body", "body": b"not found"})


def _run_asgi(port):
    freastal.serve_asgi(
        _asgi_app, host="127.0.0.1", port=port, workers=1, reuse_port=False
    )


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
