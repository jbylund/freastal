# Cross-server comparison benchmark

Regenerates the comparison table in the top-level `README.md`.

```bash
bench/compare/run.sh                                  # full run, as published
bench/compare/run.sh --rounds 1 --duration 5          # smoke test
```

Results land in `bench/compare/out/table.md` and `out/results.json`. Paste the
markdown into `README.md`; keep the JSON if you want to defend a number later.

## Why it runs in Docker

freastal targets Linux. The two things the table depends on most — `epoll` and
load-balancing `SO_REUSEPORT` — either behave differently or do not exist on
macOS, and multi-worker mode cannot be measured there at all. So the benchmark
runs in a Linux container.

On Apple Silicon the `arm64` image is **native**, so this is a real ARM64 Linux
measurement, not emulation. `run.sh` refuses to run a non-native platform
rather than produce numbers from QEMU.

It is still a container on a shared desktop. The recorded provenance says so,
and `loopback: true` is in the JSON — loopback carries the usual
`__wake_up_sync_key` scheduling artifact, so treat these as comparative
figures between servers measured identically, not as absolute capacity.

## What it measures

Five configurations, all serving the same body with the same headers:

| row | launched as |
|---|---|
| gunicorn+uvicorn, ASGI | `gunicorn -k uvicorn_worker.UvicornWorker -w N` |
| bjoern, WSGI | one listening socket, `N` pre-forked processes |
| freastal, WSGI | `freastal.serve(..., workers=N)` |
| freastal, ASGI | `freastal.serve_asgi(..., workers=N)` |
| freastal, TLS 1.3 | `freastal.serve(..., certfile=..., keyfile=...)` |

TLS is WSGI-only because `serve_asgi()` takes no `certfile`/`keyfile`. That
looks like an oversight rather than a design choice.

## Three fairness traps this harness exists to avoid

Each of these was hit while building it, and each silently produced a
plausible-looking but wrong table.

**1. The application must set `Content-Length`.** freastal computes it when the
app omits it; bjoern does not, and falls back to `Transfer-Encoding: chunked`.
Chunking splits the response into several small writes, which collides with the
peer's delayed ACK and costs ~40 ms per request:

| bjoern, 500B, 4 workers | rps | p50 |
|---|---:|---:|
| app omits `Content-Length` | 970 | 41.1 ms |
| app sets it | ~685,000 | 45 µs |

A 700x difference that has nothing to do with server speed. `apps.py` sets it
explicitly for every server.

**2. uvicorn needs its `[standard]` extras.** Bare `uvicorn` falls back to
plain asyncio and the pure-Python `h11` parser. Its own deployment docs tell
you to install `uvicorn[standard]`, which brings `uvloop` and `httptools`:

| gunicorn+uvicorn, 500B, 4 workers | rps | vs freastal WSGI |
|---|---:|---:|
| bare `uvicorn` | ~87,000 | 9.45x |
| `uvicorn[standard]` | ~341,000 | 2.34x |

Benchmarking the first is benchmarking a misconfiguration. The harness records
which loop and parser uvicorn actually resolved, and prints `MISCONFIGURED` in
the table if the accelerators are missing, so this cannot regress quietly.

**3. A stale server on a reused port.** Every server is verified before load —
it must answer `200` with a body of exactly the expected length — because a
leftover process answers happily and yields numbers for the wrong binary.

## Method

Servers are **interleaved**: each round measures every server once, and the
reported figure is the per-server median across rounds. Running each server to
completion in turn would let thermal drift or a noisy neighbour land entirely
on one row.

Rounds where either arm saw socket errors or non-2xx replies are dropped from
the median, and the count is reported.

Everything is version-pinned in the `Dockerfile` — libuv, gunicorn, uvicorn,
uvicorn-worker, bjoern — because the point is that a published number can be
regenerated. Bumping a pin invalidates the recorded table; re-run rather than
hand-edit.

## Known gaps

- **Single host, loopback.** No separate load generator, so the client competes
  with the servers for CPU. A two-machine setup would be better; the numbers
  here are comparative, not absolute.
- **`wrk` is not a fixed-rate generator.** It reports throughput at saturation,
  so the latency figures are queueing latencies under overload, not
  service-time latencies. Useful for comparison, misleading if read as "what a
  user experiences".
- **No HTTP keep-alive-off row**, so per-connection setup cost is not measured.
  `wrk` cannot exhaust the ephemeral port range fast enough to make that
  reliable inside a container anyway.
- **bjoern is pre-forked by hand** since it has no worker option, which is not
  how anyone deploys it (usually behind a process manager).
