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
        # Unset means "auto": on where SO_REUSEPORT load-balances, off on macOS,
        # where the workers share the parent's listening socket instead.  Set
        # BENCH_REUSEPORT to pin it either way for a like-for-like comparison.
        reuse_port=(
            bool(int(os.environ["BENCH_REUSEPORT"]))
            if "BENCH_REUSEPORT" in os.environ
            else None
        ),
    )
