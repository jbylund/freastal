# #34: bench: run the server and load generator in separate containers with an explicit 1500 MTU

- **Original URL:** https://github.com/jbylund/freastal/issues/34
- **Author:** jbylund
- **Created:** 2026-09-03T01:39:22Z
- **Labels:** enhancement

## Summary

`bench/compare/run.sh` runs the server and `wrk` in the *same* container, talking over `127.0.0.1`. The published table says `loopback`, so this is not misreported — but it measures a narrower thing than "freastal with TLS" suggests, and it cannot be widened by simply pointing the load generator at a routable address.

## Why changing the address does not work

Traffic to an address local to the host never leaves loopback. Linux resolves it via the `local` routing table and selects `lo` as the output device. Observed in a container on the current setup:

```
inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
--- ip route get 172.17.0.2 ---
local 172.17.0.2 dev lo  src 172.17.0.2
```

Connecting to the container's own `eth0` address, or to a host's `192.168.x.x` from that host, gives the same MTU 65536 loopback path with a different string in the URL. That would be worse than the status quo: the provenance line would say "LAN" while the kernel did loopback.

## Second trap: Docker Desktop's default bridge is not 1500

```
11: eth0@if26: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 65535
```

So splitting into two containers is not on its own sufficient — on the default bridge a 12KB response is still one segment. The MTU has to be pinned explicitly.

## Proposed change

Server in one container, `wrk` in another, on a network created with the MTU set:

```sh
docker network create --opt com.docker.network.driver.mtu=1500 bench-lan
```

Verified to take effect:

```
11: eth0@if29: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500
172.22.0.2/16
```

Traffic then goes veth -> bridge -> veth with real TCP segmentation and a real softirq path. This should visibly move the 12KB TLS rows, which today encrypt one record into a single packet — a case that cannot occur against a real client.

Work involved:

- split the single `docker run` in `run.sh` into a server container and a client container on `bench-lan`, with teardown on exit (including the network)
- the server must bind `0.0.0.0` rather than loopback; `harness.py:verify()` and the `wrk` target URL both currently hardcode `127.0.0.1`
- `harness.py` starts and reaps server processes directly via `subprocess` + pgid, which assumes it is in the same container as the server. Splitting means either running `harness.py` in the server container and only `wrk` remotely, or giving it a control channel. The former is much less invasive.
- record the MTU and the topology in the provenance block, replacing the `loopback` note

## Related

Independent of, but complementary to, the connection-churn row discussed in #30. Neither subsumes the other: this issue is about the record/packet path, that one is about the handshake path.

## Follow-up, deliberately not in scope here

`tc netem` for RTT and loss (`--cap-add=NET_ADMIN` suffices; confirmed working: `tc qdisc add dev eth0 root netem delay 25ms 5ms distribution normal loss 0.1%`). That is the change that makes "what a remote browser sees" meaningful, and it is where #28's extra round trip becomes 25ms rather than microseconds.

It should land as a **separate table**, not extra rows here. Once there is RTT, wrk's throughput figure is governed by the bandwidth-delay product and the congestion window rather than by the server, so it answers a different question (time-to-first-byte, handshake cost) and needs its own columns. Mixing the two would undermine the existing "how to read this" section.

## Comments

**jbylund** (2026-09-03T01:54:52Z):

## Alternative to the control-channel problem: a port manifest

The "Work involved" section above frames the hard part as getting `harness.py` to start and reap servers across a container boundary, and suggests keeping it in the server container. That is worse than it looks: the server container would then need the Docker socket mounted to invoke `wrk` in the client container, which is a lot of privilege for a benchmark script.

A better shape — no Docker socket anywhere:

- the **server container** starts each candidate on a deterministic port and writes a manifest (port -> `{label, proto, tls, workers, body}`) to a shared volume
- the **client container** reads the manifest and picks what to measure purely by port

The client becomes dumb. No control channel, no orchestration coupling, no socket mounting.

The split is also smaller than the issue implies: `servers.py` already binds `0.0.0.0`, and gunicorn is launched with `0.0.0.0:{port}`. Only `verify()` and the two `wrk` URLs in `measure_one()` hardcode `127.0.0.1`.

## Scope the manifest per generation, not globally

Bringing up every candidate at once has three costs worth avoiding.

**1. It makes the stale-port hazard easier to hit.** The module docstring already calls this out:

> Every server is verified before load - the harness asserts it answers 200 with a body of the expected length - because a stale process on a reused port produces plausible-looking numbers for the wrong binary.

Deterministic ports make that more likely, not less. `verify()` must stay per-measurement even when the process was started long beforehand.

**2. The resident process count is large.** Body size and worker count are per-process (`BENCH_BODY`, `BENCH_WORKERS`), so "every candidate" is the full cross product: 6 configs x 2 bodies x {1,4} workers = ~60 processes plus gunicorn masters. Idle epoll waiters cost approximately no CPU, but at Python RSS that is several GB — enough to matter against Docker Desktop's default memory allocation, and enough to change page-cache behavior relative to the published numbers.

**3. Fresh-process-per-measurement is lost.** Today every measurement runs against a process that has served exactly one warmup plus one run. With a single up-front manifest, a config's round-3 number comes from a process that already served rounds 1 and 2.

All three go away if the manifest generation is keyed on `(round, body, workers)` rather than being global:

- server container brings up the 6 configs for one combination, writes the manifest with a generation counter
- client runs its 6 measurements, drops a done-file
- server tears down, starts the next generation

Coordination is files on the shared volume — no sockets, no Docker socket, no control channel. At most 6 resident processes instead of ~60, every measurement still gets a fresh process, and the interleaving order described in the docstring is preserved exactly: it is the same nesting the existing loop uses, cut one level higher. It also replaces 72 start/verify/kill cycles with 12.

The detail to get right is the handshake: the client must not begin generation N+1 while generation N is still shutting down, or the stale-port problem returns in a new costume. Checking the generation counter in the manifest after each teardown covers it.

## Still a re-baseline

Worth restating regardless of which shape is chosen: moving off loopback changes the environment the published table describes, so the numbers will need regenerating rather than patching, and the provenance block should record the topology and MTU.

**jbylund** (2026-09-03T02:52:59Z):

Some measurements that strengthen the case here, plus one trap in the proposed fix and three load-shape changes that this issue enables but does not itself cover.

## The client/server CPU contention is currently binding, measured

Container has 18 CPUs. freastal WSGI, 500B, plaintext, 12s runs, server CPU sampled from `/proc/<pid>/stat` during the run:

| workers | wrk threads | conns | rps | server cores used | saturation |
|---:|---:|---:|---:|---:|---:|
| 4 | 2 | 40 | 298,959 | 2.37 | 59% |
| 4 | **4** | **40** | **849,940** | 3.54 | **88%** |
| 4 | 8 | 40 | 552,923 | 5.50 | 138% |
| 4 | 4 | 80 | 520,935 | 3.93 | 98% |
| 4 | 4 | 160 | 402,877 | 3.54 | 88% |
| **8** | **8** | **80** | **1,158,728** | 7.68 | 96% |

Three things follow:

1. **At the published operating point the workers are only 88% busy.** The server is not the constraint, so the published 4-worker rps is not a server measurement.
2. **The apparent ~856k ceiling is not a ceiling.** 8 workers reach 1.16M rps. `-t4 -c40` is simply the wrong shape for 4+ workers.
3. **Adding client threads at fixed concurrency costs throughput while raising server CPU** (850k → 553k, server 3.54 → 5.50 cores). That is cross-CPU wakeup and locality cost, i.e. the two sides fighting for cores — exactly what this issue is about.

Corroborating signature in the existing published data: scaling from 1 to 4 workers is inversely correlated with single-worker speed — gunicorn+uvicorn 3.34x, bjoern 3.07x, freastal ASGI 2.88x, freastal WSGI 2.40x. The faster the server, the less headroom before it hits the rig's shared limit. The current table therefore makes the fastest server look like the worst scaler.

And the 4-worker plateau tracks *client* work rather than server work: 856k (500B plaintext) → 802k (client memcpys 12KB) → 778k (client decrypts 500B) → 512k (client decrypts 12KB). See #33.

## Trap: separate containers do not give separate CPUs

Two containers on the same host still share one CPU pool. `docker network create --opt ...mtu=1500` fixes the packet path, which is what this issue is actually about, but it does **not** reduce the contention measured above — `wrk` and the workers will still be scheduled across the same 18 CPUs.

If CPU isolation is wanted alongside the packet path, it needs `--cpuset-cpus` on both containers, partitioning disjointly, e.g. server `0-7` and client `8-15`. Worth deciding deliberately whether that is in scope here or a follow-up, because the two problems are independent and either can be fixed without the other. The provenance block should record the cpuset either way, since a reader cannot otherwise tell whether the number is CPU-contended.

## Three load-shape changes this unblocks

None of these are in scope for this issue, but they are what makes the resulting numbers meaningful, and they are the reason `-t4 -c40` should not survive the split unchanged.

**1. Sweep concurrency instead of fixing it.** A single shape cannot be fair across servers that differ by 3x. TechEmpower runs 16/32/64/128/256/512 concurrent and reports each framework's best, precisely so a fast implementation is not pinned to a shape that suits a slow one. Reporting the curve, or the argmax plus the shape that produced it, removes the experimenter degree of freedom that per-server hand-tuning would introduce.

**2. Add a pipelined row.** This is the standard answer to "the client cannot generate enough load," and it is how TechEmpower's Plaintext test works — wrk driven by a Lua script at 16-deep pipelining. Amortizing the round trip across 16 requests cuts client CPU per request substantially and lets a fast server actually saturate. The script is small:

```lua
init = function(args)
  local r = {}
  for i = 1, 16 do r[i] = wrk.format(nil, "/") end
  req = table.concat(r)
end
request = function() return req end
```

freastal already supports pipelining and has coverage for it, including `test_two_records_in_one_segment` added in #27.

Caveat worth writing into the table's "how to read this": a pipelined figure measures request-processing throughput with the round trip removed. It is the right way to compare parsing and dispatch efficiency and the wrong way to describe what a browser sees — browsers do not pipeline, HTTP/2 multiplexes instead. It should be an additional row, not a replacement, the way TechEmpower keeps both.

**3. Record server CPU utilization in `results.json`.** The cheapest and most durable of the three. Sum `utime+stime` across the worker pgid before and after each run and divide by wall time. Every conclusion above came from that one number, and it is not currently captured — so today a reader cannot distinguish "the server is at its limit" from "the client ran out of CPU," which is the whole question this issue and #33 are circling.

## Reference

TechEmpower's rig is the methodology precedent for all of the above: separate physical machines on a dedicated 10GbE switch, concurrency sweep, pipelining for the throughput test, warmup then fixed-duration rounds. This issue is step one of that list; items 1-3 are steps two and three.

**jbylund** (2026-09-03T02:59:58Z):

**Correcting one number in my comment above, and adding the client-side CPU measurement it was missing.**

The earlier run had a process-cleanup bug — `pkill` without `-9` plus a 1s settle, so server processes accumulated across configs. It is visible in hindsight as an impossible row reporting *1 worker using 3.14 cores*. Rerun with `pkill -9`, a 1.5s settle, an `EXIT` trap, and CPU sampled for both sides during the run:

| workers | wrk threads | conns | rps | srv cores | wrk cores | total cores | srv sat | rps per core |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 4 | 40 | 868,207 | 3.68 | 3.78 | 7.46 | 92% | **116k** |
| 4 | 8 | 40 | 511,948 | 3.90 | 3.50 | 7.40 | 98% | **69k** |
| 8 | 8 | 80 | **1,469,871** | 7.28 | 7.61 | 14.89 | 91% | 99k |

## What changes

**Retracted:** I wrote that going 4 → 8 wrk threads raised server CPU to 5.50 cores. It does not — it goes 3.68 → 3.90. That 5.50 was accumulated leftover processes, not real work.

The corrected version is a cleaner result: **total CPU is flat at ~7.4 cores while throughput falls 41%.** Efficiency drops from 116k to 69k rps per core. Same machine, same CPU spend, far less delivered — which is contention, not capacity, and is the point the original comment was reaching for.

**Also corrected:** 8 workers / 8 threads / 80 conns is **1,469,871 rps**, not the 1.16M I reported (same cleanup bug). So the published 856k figure is roughly **59% of what this rig can already deliver** without any code change.

**Unchanged:** the 4/4/40 row reproduces across both runs — 849,940 vs 868,207 rps (2% apart), server saturation 88% vs 92%. Every conclusion in the comment above rests on that row and stands.

## The new finding: the client costs as much as the server

At the published operating point, **wrk burns 3.78 cores against the server's 3.68** — a 1.03:1 ratio. Roughly half of all CPU spent producing the published number is spent by the load generator.

That is the most direct statement of why this rig cannot measure the server, and it also settles which kind of contention this is: total consumption is **7.46 of 18 cores**, so about 10.5 cores are idle. The rig is not CPU-starved. The loss is scheduling and locality — client and server threads on the same cores, and loopback delivering receive processing in softirq on the sending CPU, so each request bills both sides and they interleave badly.

Two practical consequences for this issue:

- **`--cpuset-cpus` should partition roughly in half, not favour the server.** A 12-server / 6-client split would starve the client, since the client needs about as many cores as the server.
- **It reinforces that separate containers alone will not fix this** (the point in my comment above). Two containers sharing 18 CPUs still interleave; the CPU headroom is already there and is not being converted into throughput.

Method note, for anyone reproducing: sample `utime+stime` from `/proc/<pid>/stat` for both process trees *during* the run. Sampling after `wrk` exits reads zero, because the process is gone — which is how I got the missing client column the first time.

