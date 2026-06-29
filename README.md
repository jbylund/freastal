# freastal

A fast WSGI/ASGI server for Python, built as a C extension on top of [libuv](https://libuv.org/) and [picohttpparser](https://github.com/h2o/picohttpparser). Optional TLS 1.3 via [picotls](https://github.com/h2o/picotls).

*Freastal* (IPA: /ˈfʲɾʲasˠtəl/) is Irish Gaelic for "service."

## Performance

Benchmarked against gunicorn+uvicorn (the most common production Python stack) as baseline. 30-second runs, `wrk -t4 -c40`, 4 worker processes, ARM64 Linux.

### 500B response

| Server | Protocol | Req/s | p50 | p99 | vs baseline |
|--------|----------|------:|----:|----:|------------:|
| **gunicorn+uvicorn** | **ASGI** | **~225k** | **156µs** | **476µs** | **1.00×** |
| bjoern | WSGI | ~370k | 90µs | 390µs | 1.65× |
| freastal | WSGI | ~424k | 78µs | 312µs | 1.88× |
| freastal | ASGI | ~408k | 81µs | 317µs | 1.81× |
| freastal | TLS 1.3 | ~421k | 78µs | 342µs | 1.87× |

### 12KB response

| Server | Protocol | Req/s | p50 | p99 | vs baseline |
|--------|----------|------:|----:|----:|------------:|
| **gunicorn+uvicorn** | **ASGI** | **~201k** | **173µs** | **524µs** | **1.00×** |
| bjoern | WSGI | ~293k | 120µs | 360µs | 1.46× |
| freastal | WSGI | ~299k | 114µs | 391µs | 1.49× |
| freastal | ASGI | ~295k | 115µs | 409µs | 1.47× |
| freastal | TLS 1.3 | ~279k | 121µs | 555µs | 1.39× |

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
- **io_uring fixed-buffer path** (Linux, optional) — when built with `liburing`, responses > 4 KB are copied into pre-registered kernel buffers and sent with `io_uring_prep_write_fixed`, eliminating per-write `get_user_pages()` overhead. libuv ≥ 1.45 also transparently batches `accept`/`read`/`write` via io_uring regardless of this flag.
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

# Debian/Ubuntu with io_uring fixed-buffer path (Linux ≥ 5.6)
apt-get install libuv1-dev libssl-dev liburing-dev
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
