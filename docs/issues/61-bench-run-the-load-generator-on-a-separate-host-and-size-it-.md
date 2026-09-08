# #61: bench: run the load generator on a separate host, and size it from the bandwidth the table actually needs

- **Original URL:** https://github.com/jbylund/freastal/issues/61
- **Author:** jbylund
- **Created:** 2026-09-04T02:36:43Z
- **Labels:** enhancement

## Summary

Run the server and `wrk` on two hosts across a real network, replacing the co-resident loopback
setup. This supersedes #34 — two instances give real NICs, real MTU and real segmentation directly,
rather than approximating them with two containers on one host.

The reason to file this separately from #34 is that the *sizing* turns out to be the whole problem,
and it is decided by arithmetic that has not been done anywhere yet.

## What each published row needs from the wire

Measured bytes on the wire: a 500B body is **537 B** of response, plus ~80 B of request.

| row | req/s today | wire | link needed |
|---|---:|---:|---:|
| 500B, WSGI, 4 workers | 856k | 0.53 GB/s | **4.2 Gbps** |
| 500B, best measured | 903k | 0.56 GB/s | **4.5 Gbps** |
| 12KB, WSGI, 4 workers | 802k | 9.76 GB/s | **78 Gbps** |
| 12KB, ASGI, 4 workers | 757k | 9.21 GB/s | **74 Gbps** |

And what a given link allows, before the server is even considered:

| link | 500B | 12KB |
|---:|---:|---:|
| 5 Gbps | 1,012,966 | 51,347 |
| 10 Gbps | 2,025,932 | 102,695 |
| 25 Gbps | 5,064,830 | 256,737 |
| 100 Gbps | 20,259,319 | 1,026,947 |

So: **the 500B rows need ~5 Gbps and are cheap to measure honestly. The 12KB rows need 100GbE
networking or they are link-bound** — at 25 Gbps every server in the table flattens against the wire
at ~257k and the comparison ranks NICs rather than servers.

## The finding this produces

The 12KB numbers in `README.md` are **only achievable on loopback**. No deployment serves 800k x
12KB/s through a NIC without 100GbE. That is worth publishing as a result rather than engineering
around: above a certain body size the server stops being the interesting variable.

It is also the most likely explanation for #33 ("the 12KB TLS cell does not reconcile with
per-request cycle cost") — a cell that does not reconcile because it is measuring memory bandwidth
rather than request processing would reconcile immediately on a real link.

## Sizing

- **Server host: more vCPU than workers.** On a 4-vCPU box, 4 workers leave nothing for softirq and
  NIC interrupt handling, so the network steals from the workers and the run measures contention.
  8 vCPU for 4 workers is the safer ratio. With the client off-box, all of it is genuinely the
  server's — which is what makes #55's saturation column trustworthy here.
- **Client host at least as large.** `wrk` is less efficient per core than freastal; locally it
  needed roughly as much CPU as the server to drive it. An undersized client just recreates the
  problem this issue exists to escape.
- **Same AZ, cluster placement group.**
- **Check *sustained*, not burst, bandwidth.** Smaller instance types advertise "up to N Gbps" on a
  credit system and the baseline is lower. 4.5 Gbps sustained is the bar for the 500B rows.

## Suggested split, so the expensive part is a one-off

1. A modest pair (10 Gbps class) for everything recurring: the 500B rows, the `vs baseline` ratios,
   and the concurrency sweep.
2. One short session on a 100GbE-class pair to establish the 12KB ceiling once, published as a
   datapoint with its own provenance block rather than a standing row.
3. For large bodies on the cheap pair, report **CPU per request** rather than peak throughput. It is
   far less bandwidth-sensitive: drive at whatever the link allows and divide server CPU by
   requests served. Caveat worth stating in the output — an underutilised event loop costs slightly
   *more* per request, because fewer events batch per wakeup, so a link-limited row overstates
   per-request cost a little.

## Before spending the money, verify in this order

Each of these has already burned a measurement in this project, so they are worth doing as a
checklist rather than discovering them at 100 Gbps:

1. `iperf3` between the two hosts. Confirm the *sustained* figure matches the instance type's claim.
   A path that is slower than advertised silently caps everything downstream.
2. Point `wrk` at a trivial static server and confirm the client can generate more requests/s than
   freastal can serve. If it cannot, the run measures the client.
3. Confirm the server's CPU is the binding constraint at the shape chosen — #55 reports this
   directly now. A row where the server sits below ~90% is not a capacity number.
4. Record topology, MTU and both instance types in the provenance block. That is #34's acceptance
   criterion and it is the difference between a number and a claim.

## Consequences

- **Everything re-baselines.** Different CPU and a real network mean every figure changes; the table
  needs regenerating rather than patching, and the provenance block needs the new topology.
- **For *comparison*, loopback was defensible** — every server faced the same handicap. This setup
  is for absolute numbers and for exercising the record/packet path. Worth stating in "how to read
  this" which question the table answers, because it changes what "3.2x baseline" means.

## Supersedes / relates

- Supersedes #34 (two containers, pinned MTU) — the same goal, achieved directly.
- Likely answers #33.
- #32 and #30 are orthogonal but become cheaper to run honestly on this setup.

## Comments

**jbylund** (2026-09-04T03:16:21Z):

Use a c8gn.8xlarge (or 2 as it were)

https://instances.vantage.sh/aws/ec2/c8gn.8xlarge?currency=USD&region=us-east-2

