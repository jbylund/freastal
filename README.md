# freastal

A fast WSGI/ASGI server for Python, built as a C extension on top of [libuv](https://libuv.org/) and [picohttpparser](https://github.com/h2o/picohttpparser). Optional TLS 1.3 via [picotls](https://github.com/h2o/picotls).

*Freastal* (IPA: /ˈfʲɾʲasˠtəl/) is Irish Gaelic for "service."

## Performance

Regenerate with `bench/compare/run.sh`, which runs every server in a Linux
container under identical conditions and writes this table plus a JSON record.
See [bench/compare/README.md](bench/compare/README.md) for the method.

| | |
|---|---|
| Platform | aarch64, Debian GNU/Linux 13 (trixie) (kernel 7.0.12-linuxkit) |
| CPU | Apple M5 Max, 18 available |
| Python | 3.12.14 |
| libuv | 1.52.1 |
| Load | `wrk -t4 -c40`, 30s x 3 rounds (median), loopback |
| Versions | gunicorn 23.0.0, uvicorn 0.34.0 (uvloop + httptools), bjoern 3.2.2 |
| freastal | b1b4b69 |


### 500B response

| Server | Protocol | TLS | Workers | Req/s | p50 | p99 | vs baseline | between | within |
|--------|----------|:---:|--------:|------:|----:|----:|------------:|--------:|-------:|
| **gunicorn+uvicorn** | **ASGI** | **no** | **1** | **~112k** | **318us** | **672us** | **1.00x** | **6%** | **4%** |
| bjoern | WSGI | no | 1 | ~256k | 150us | 249us | 2.28x | 2% | 3% |
| freastal | WSGI | no | 1 | ~357k | 103us | 215us | 3.18x | 4% | 10% |
| freastal | ASGI | no | 1 | ~277k | 133us | 271us | 2.48x | 3% | 8% |
| freastal | WSGI | yes | 1 | ~302k | 123us | 244us | 2.70x | 5% | 8% |
| freastal | ASGI | yes | 1 | ~238k | 158us | 292us | 2.13x | 3% | 9% |
| **gunicorn+uvicorn** | **ASGI** | **no** | **4** | **~374k** | **94us** | **225us** | **1.00x** | **3%** | **7%** |
| bjoern | WSGI | no | 4 | ~786k | 39us | 123us | 2.10x | 6% | 5% |
| freastal | WSGI | no | 4 | ~856k | 34us | 122us | 2.29x | 2% | 4% |
| freastal | ASGI | no | 4 | ~799k | 39us | 126us | 2.14x | 10% | 5% |
| freastal | WSGI | yes | 4 | ~778k | 40us | 129us | 2.08x | 7% | 5% |
| freastal | ASGI | yes | 4 | ~762k | 40us | 125us | 2.04x | 3% | 5% |

### 12KB response

| Server | Protocol | TLS | Workers | Req/s | p50 | p99 | vs baseline | between | within |
|--------|----------|:---:|--------:|------:|----:|----:|------------:|--------:|-------:|
| **gunicorn+uvicorn** | **ASGI** | **no** | **1** | **~106k** | **334us** | **714us** | **1.00x** | **4%** | **7%** |
| bjoern | WSGI | no | 1 | ~220k | 176us | 260us | 2.08x | 2% | 2% |
| freastal | WSGI | no | 1 | ~319k | 114us | 241us | 3.01x | 3% | 10% |
| freastal | ASGI | no | 1 | ~261k | 143us | 286us | 2.47x | 6% | 9% |
| freastal | WSGI | yes | 1 | ~190k | 200us | 405us | 1.79x | 2% | 8% |
| freastal | ASGI | yes | 1 | ~163k | 233us | 444us | 1.54x | 2% | 12% |
| **gunicorn+uvicorn** | **ASGI** | **no** | **4** | **~353k** | **101us** | **219us** | **1.00x** | **5%** | **6%** |
| bjoern | WSGI | no | 4 | ~621k | 51us | 141us | 1.76x | 2% | 5% |
| freastal | WSGI | no | 4 | ~802k | 39us | 108us | 2.27x | 8% | 4% |
| freastal | ASGI | no | 4 | ~757k | 42us | 126us | 2.14x | 4% | 7% |
| freastal | WSGI | yes | 4 | ~512k | 65us | 157us | 1.45x | 8% | 4% |
| freastal | ASGI | yes | 4 | ~508k | 66us | 176us | 1.44x | 5% | 3% |

**How to read this.** `between` is the spread across the three interleaved
rounds, `within` is wrk's own per-thread variation inside a run. Both are
published because a median over scattered samples looks more precise than it
is. At one worker every row above is cleanly separated. At four workers the
middle of the pack is not: freastal ASGI, bjoern, and both TLS variants all
land within a few percent of each other at 500B, and their per-round ranges
overlap, so treat their ordering as unresolved rather than as shown.

These are comparative figures on one host over loopback, not absolute capacity.
`wrk` saturates the server rather than holding a fixed rate, so the latency
columns are queueing latencies under overload.

The application sets `Content-Length` explicitly and uvicorn is installed with
its `[standard]` extras (uvloop + httptools). Both matter: without the header
bjoern falls back to chunked encoding and collapses to ~1k rps, and without the
extras uvicorn runs on plain asyncio and h11 at roughly a third of its real
throughput. Benchmarking either misconfiguration would flatter freastal by a
large factor.

## Installation

Pre-built wheels for Linux (x86\_64, aarch64) and macOS (arm64, x86\_64) are available on PyPI:

```bash
pip install freastal
```

Building from source requires libuv ≥ 1.44, a C compiler, and (optionally) OpenSSL for TLS support. See [Building from source](#building-from-source).

## Usage

### WSGI

```python
import freastal

def app(environ, start_response):
    body = b"Hello, world!"
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [body]

freastal.serve(app, host="0.0.0.0", port=8000, workers=4)
```

### ASGI

```python
import freastal

async def app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200,
                "headers": [[b"content-type", b"text/plain"]]})
    await send({"type": "http.response.body", "body": b"Hello, world!"})

freastal.serve_asgi(app, host="0.0.0.0", port=8000, workers=4)
```

### TLS 1.3

```python
freastal.serve(app, host="0.0.0.0", port=8000, workers=4,
               certfile="/path/to/cert.pem", keyfile="/path/to/key.pem")
```

TLS requires OpenSSL headers at build time. Wheels published to PyPI include TLS support.

## Architecture

- **libuv** — cross-platform event loop; io\_uring-ready on Linux (libuv ≥ 1.45 batches syscalls automatically)
- **picohttpparser** — SSE4.2/NEON SIMD HTTP/1.1 parser from the h2o project; vendored
- **picotls** — TLS 1.3 library from the h2o project; vendored, gated by `FREASTAL_TLS`
- Single `uv_write` per response — headers and body sent together, no extra copy
- HTTP/1.1 keep-alive: connections re-armed in-place without close/reopen; `TCP_NODELAY` set on every accepted socket
- Slab allocator for per-connection state — no per-request malloc on the hot path
- Pre-interned Python strings for all WSGI/ASGI environ keys
- GIL released for the duration of the libuv event loop; acquired only when calling the WSGI/ASGI application and touching Python response objects
- `SO_REUSEPORT` (`UV_TCP_REUSEPORT`) for kernel-level load balancing across worker processes

**Multi-process model:** `workers=N` forks N independent OS processes, each with its own libuv loop and Python interpreter (and therefore its own GIL). The kernel distributes incoming connections across workers via `SO_REUSEPORT`.

**ASGI event loop bridge (libuv ↔ asyncio):**

freastal runs asyncio inside the libuv event loop rather than the other way around. A `uv_check_t` steps asyncio after each I/O poll; a `uv_poll_t` on asyncio's selector fd wakes libuv when external async I/O (database calls, aiohttp, etc.) completes.

## Building from source

```bash
# macOS
brew install libuv openssl@3
pip install freastal --no-binary freastal

# Debian/Ubuntu
apt-get install libuv1-dev libssl-dev
pip install freastal --no-binary freastal
```

picohttpparser and picotls are vendored — no extra steps required.

## Requirements

- Python ≥ 3.10
- Linux or macOS
- libuv ≥ 1.44 (shared library, found via pkg-config or standard include paths)
- OpenSSL (optional, for TLS 1.3)

## License

MIT
