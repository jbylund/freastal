"""Hello-world ASGI app used for the freastal benchmarks (500B body, README shape)."""

import os

import freastal

BODY = b"x" * int(os.environ.get("BENCH_BODY", "500"))
HEADERS = [[b"content-type", b"text/plain"]]


async def app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": HEADERS})
    await send({"type": "http.response.body", "body": BODY})


if __name__ == "__main__":
    freastal.serve_asgi(
        app,
        host="127.0.0.1",
        port=int(os.environ.get("BENCH_PORT", "8123")),
        workers=int(os.environ.get("BENCH_WORKERS", "1")),
        # macOS libuv has no load-balancing SO_REUSEPORT; single worker here.
        reuse_port=bool(int(os.environ.get("BENCH_REUSEPORT", "0"))),
    )
