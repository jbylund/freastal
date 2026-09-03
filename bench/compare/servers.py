"""The server under test, selected by $BENCH_SERVER.

Run as a subprocess by harness.py.  gunicorn is not here because it is its own
launcher; harness.py invokes its CLI against `apps:asgi_app`, which is the same
object this file serves.
"""

import os
import socket
import sys

from apps import asgi_app, wsgi_app

PORT = int(os.environ["BENCH_PORT"])
WORKERS = int(os.environ.get("BENCH_WORKERS", "4"))
SERVER = os.environ["BENCH_SERVER"]


def prefork(n):
    """Fork n-1 children; returns in each of the n processes.

    bjoern has no worker option of its own, so it gets the same shape gunicorn
    and freastal use: one listening socket, n processes accepting on it.
    """
    for _ in range(n - 1):
        if os.fork() == 0:
            return


def main():
    if SERVER == "freastal-wsgi":
        import freastal

        freastal.serve(wsgi_app, host="0.0.0.0", port=PORT, workers=WORKERS)

    elif SERVER == "freastal-asgi":
        import freastal

        freastal.serve_asgi(asgi_app, host="0.0.0.0", port=PORT, workers=WORKERS)

    elif SERVER == "freastal-wsgi-tls":
        import freastal

        freastal.serve(
            wsgi_app,
            host="0.0.0.0",
            port=PORT,
            workers=WORKERS,
            certfile=os.environ["BENCH_CERT"],
            keyfile=os.environ["BENCH_KEY"],
        )

    elif SERVER == "freastal-asgi-tls":
        import freastal

        freastal.serve_asgi(
            asgi_app,
            host="0.0.0.0",
            port=PORT,
            workers=WORKERS,
            certfile=os.environ["BENCH_CERT"],
            keyfile=os.environ["BENCH_KEY"],
        )

    elif SERVER == "bjoern":
        import bjoern

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", PORT))
        sock.listen(4096)
        sock.setblocking(False)
        prefork(WORKERS)
        bjoern.server_run(sock, wsgi_app)

    else:
        sys.exit(f"unknown BENCH_SERVER={SERVER!r}")


if __name__ == "__main__":
    main()
