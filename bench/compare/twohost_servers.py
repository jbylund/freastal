"""One entry point per server under test, selected by argv[1].

Reads BENCH_PORT / BENCH_WORKERS / BENCH_BODY from the environment so the
orchestrator does not have to know each server's own flags.
"""

import os
import sys

KIND = sys.argv[1]
PORT = int(os.environ["BENCH_PORT"])
WORKERS = int(os.environ.get("BENCH_WORKERS", "1"))
BODY = b"x" * int(os.environ.get("BENCH_BODY", "500"))
CL = str(len(BODY))

if KIND == "freastal-wsgi":
    import freastal

    def app(environ, start_response):
        start_response(
            "200 OK", [("Content-Type", "text/plain"), ("Content-Length", CL)]
        )
        return [BODY]

    if __name__ == "__main__":
        freastal.serve(app, host="0.0.0.0", port=PORT, workers=WORKERS)

elif KIND == "freastal-asgi":
    import freastal

    async def app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    [b"content-type", b"text/plain"],
                    [b"content-length", CL.encode()],
                ],
            }
        )
        await send({"type": "http.response.body", "body": BODY})

    if __name__ == "__main__":
        freastal.serve_asgi(app, host="0.0.0.0", port=PORT, workers=WORKERS)

elif KIND == "gunicorn-uvicorn":

    async def app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    [b"content-type", b"text/plain"],
                    [b"content-length", CL.encode()],
                ],
            }
        )
        await send({"type": "http.response.body", "body": BODY})

    if __name__ == "__main__":
        import gunicorn.app.base

        # uvicorn_worker is the maintained worker class; the one bundled in
        # uvicorn (uvicorn.workers.UvicornWorker) is deprecated. Fall back only
        # if the package is genuinely absent, so a missing dependency shows up
        # as a slower row rather than a crash -- and say so on stderr, because
        # a silently deprecated worker is a silently different baseline.
        try:
            import uvicorn_worker  # noqa: F401

            WORKER = "uvicorn_worker.UvicornWorker"
        except ImportError:
            WORKER = "uvicorn.workers.UvicornWorker"
            print(
                "WARNING: uvicorn-worker not installed, using the deprecated "
                "bundled worker class",
                file=sys.stderr,
            )

        class App(gunicorn.app.base.BaseApplication):
            def load_config(self):
                self.cfg.set("bind", f"0.0.0.0:{PORT}")
                self.cfg.set("workers", WORKERS)
                self.cfg.set("worker_class", WORKER)
                # access_log defaults to on and costs real throughput; error
                # level filters those records before they are formatted.
                self.cfg.set("loglevel", "error")

            def load(self):
                return app

        App().run()

elif KIND == "bjoern":
    import bjoern

    def app(environ, start_response):
        start_response(
            "200 OK", [("Content-Type", "text/plain"), ("Content-Length", CL)]
        )
        return [BODY]

    if __name__ == "__main__":
        bjoern.run(app, "0.0.0.0", PORT)

else:
    raise SystemExit(f"unknown server kind: {KIND}")
