"""The application every server under test serves.

Importable without any environment beyond BENCH_BODY, so gunicorn can load
`apps:asgi_app` directly while servers.py uses the same objects in-process.
Both protocols answer with the same body and the same single response header,
so the table measures servers rather than applications.
"""

import os

BODY = b"x" * int(os.environ.get("BENCH_BODY", "500"))

# Content-Length is set by the application, deliberately.
#
# freastal computes it for you when the app omits it; bjoern does not, and
# falls back to Transfer-Encoding: chunked.  Chunking splits one response into
# several small writes, which without TCP_NODELAY collides with the peer's
# delayed ACK and costs ~40ms per request - measured at 970 rps and a 41ms p50
# here, versus ~180k rps once the header is present.  Leaving it out would make
# the table a comparison of framing defaults rather than of servers.
WSGI_HEADERS = [("Content-Type", "text/plain"), ("Content-Length", str(len(BODY)))]
ASGI_HEADERS = [
    [b"content-type", b"text/plain"],
    [b"content-length", str(len(BODY)).encode()],
]


def wsgi_app(environ, start_response):
    start_response("200 OK", WSGI_HEADERS)
    return [BODY]


async def asgi_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": ASGI_HEADERS})
    await send({"type": "http.response.body", "body": BODY})
