"""Pure-Python ASGI protocol bridge for freastal.

run_asgi_request() is called from C (asgi_dispatch) once per HTTP request.
It creates the receive/send coroutines and schedules the ASGI app as an
asyncio Task on the loop that freastal is stepping from its uv_check_t callback.
"""

from ._freastal import asgi_send_response


def run_asgi_request(loop, app, scope, body, capsule):
    """Schedule `app(scope, receive, send)` as a Task and return it.

    The Task runs inside the asyncio loop that freastal drives from
    uv_check_t / uv_poll_t callbacks.  Because receive() returns immediately
    and send() calls back into C synchronously, a simple ASGI app completes
    in one _run_once() step with no event-loop round-trips.

    Apps that do real async I/O (await aiohttp.get(...), await db.query(...))
    work normally: their futures are resolved by asyncio's selector, which
    freastal monitors via a uv_poll_t on asyncio's selector fd.
    """
    status_cell = [None]
    headers_cell = [None]

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(event):
        t = event["type"]
        if t == "http.response.start":
            status_cell[0] = event["status"]
            headers_cell[0] = list(event.get("headers", []))
        elif t == "http.response.body":
            asgi_send_response(
                capsule,
                status_cell[0],
                headers_cell[0],
                event.get("body", b""),
            )

    return loop.create_task(app(scope, receive, send))
