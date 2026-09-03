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

Six configurations, all serving the same body with the same headers:

| row | launched as |
|---|---|
| gunicorn+uvicorn, ASGI | `gunicorn -k uvicorn_worker.UvicornWorker -w N` |
| bjoern, WSGI | one listening socket, `N` pre-forked processes |
| freastal, WSGI | `freastal.serve(..., workers=N)` |
| freastal, ASGI | `freastal.serve_asgi(..., workers=N)` |
| freastal, WSGI + TLS 1.3 | `freastal.serve(..., certfile=..., keyfile=...)` |
| freastal, ASGI + TLS 1.3 | `freastal.serve_asgi(..., certfile=..., keyfile=...)` |

Each is measured at every `--worker-counts` and `--bodies` value, so the
published table is that grid: protocol x TLS x workers x body size. Comparing
along one axis at a time is the point - TLS against plaintext at the same
worker count, or one worker against four for the same server.

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

## Was the server working, or the client?

Every figure `wrk` reports describes what the *client* observed, so a row can
be a capacity measurement or an artefact of the harness and look identical
either way. This is not hypothetical: in #48/#50 macOS multi-worker was
concluded three times to give no throughput gain, from measurements that were
entirely client-bound.

So the harness samples `utime + stime` for the server's whole process group and
for the `wrk` process every `--cpu-interval` seconds (0.5s by default) across
the **measured** run - the warmup is excluded because sampling starts when the
measured `wrk` is spawned. `srv` and `cli` in the table are the medians:

| | meaning |
|---|---|
| `srv` | server CPU as a percentage of `workers` cores. 400% possible at `-w4`. |
| `cli` | `wrk` CPU as a percentage of the cores it could use, `min(threads, cpus)`. |

Read the pair, never `srv` alone - low server CPU says the server was not the
limit but not what was:

| srv | cli | reading | what to do |
|---|---|---|---|
| high | low | **server-limited** | a real capacity number; trust the row |
| low | high | **client-limited** | a property of the harness; the server has headroom the table is not showing |
| low | low | **neither** | too few requests in flight, or the loopback path is the limit; raise `-c` |
| high | high | **both-saturated** | valid for *this* config, but the client has no headroom left, so a larger worker count cannot be measured without raising `-t` |

`machine-limited` is a separate check, not "both of them at once": it fires only
when server plus client exceed 90% of the cores the container may use. At
`-w4 -t4` on an 18-core host both sides can sit on their own budget with two
thirds of the machine idle, which is `both-saturated`, not a machine limit.

These are thresholds - 80% of a side's own budget, 90% of the box - on a
continuous quantity. A row that lands on the line should be read from `srv` and
`cli` themselves; the word exists so an obviously client-bound row cannot be
published as a capacity number without someone noticing.

`results.json` carries more, as a per-config median under `cpu` and per round
under `cpu_all`, so a surprising median can be traced to the round that made it:

- `server_peak_cores` and `ramp_s` - a mean cannot tell a server pinned for 30s
  from one that idled for 10s and then ran flat out. A non-zero `ramp_s` means
  the 5s warmup did not finish warming the server and the mean understates it.
- `worker_cores`, one entry per worker, busiest first, and
  `worker_imbalance_pct`. One worker at 100% while three sit at 20% sums to the
  same number as four at 40%; only this distinguishes them. A rank at ~0 is a
  worker that died. Workers are identified as the top `workers` pids by CPU,
  which gets gunicorn's master, freastal's joining parent and bjoern's
  parent-is-also-a-worker shape right without hard-coding any of them.
- `machine_sat_pct`, `pids`, `window_s`, `samples`.
- `sampler_cpu_pct_of_core` - the sampler's own thread CPU, measured with
  `time.thread_time()` rather than asserted, because the instrument competes
  for the same cores as the thing it measures. Measured at ~0.05% of one core
  at the default period; see the A/B in the issue #54 notes.

Pass `--cpu-interval 0` to switch sampling off entirely. On a host without
`/proc` every CPU field is `null` and the columns read `n/a`.

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
