"""One entry point per server under test, selected by argv[1].

Reads BENCH_PORT / BENCH_WORKERS / BENCH_BODY from the environment so the
orchestrator does not have to know each server's own flags.
"""

import os
import sys

COMPARE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(COMPARE_DIR))
for path in (COMPARE_DIR, REPO_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from apps import asgi_app, wsgi_app


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: twohost_servers.py SERVER_KIND")
    kind = sys.argv[1]
    port = int(os.environ.get("BENCH_PORT", "9200"))
    workers = int(os.environ.get("BENCH_WORKERS", "1"))

    if kind == "freastal-wsgi":
        import freastal

        freastal.serve(wsgi_app, host="0.0.0.0", port=port, workers=workers)

    elif kind == "freastal-asgi":
        import freastal

        freastal.serve_asgi(asgi_app, host="0.0.0.0", port=port, workers=workers)

    elif kind == "gunicorn-uvicorn":
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
                self.cfg.set("bind", f"0.0.0.0:{port}")
                self.cfg.set("workers", workers)
                self.cfg.set("worker_class", WORKER)
                # access_log defaults to on and costs real throughput; error
                # level filters those records before they are formatted.
                self.cfg.set("loglevel", "error")

            def load(self):
                return asgi_app

        App().run()

    elif kind == "bjoern":
        import bjoern

        bjoern.run(wsgi_app, "0.0.0.0", port)

    else:
        raise SystemExit(f"unknown server kind: {kind}")


if __name__ == "__main__":
    main()
