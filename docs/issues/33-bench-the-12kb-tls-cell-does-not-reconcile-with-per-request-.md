# #33: bench: the 12KB TLS cell does not reconcile with per-request cycle counts — the published 36% may be partly load-generator contention

- **Original URL:** https://github.com/jbylund/freastal/issues/33
- **Author:** jbylund
- **Created:** 2026-09-03T01:38:47Z
- **Labels:** bug

## Summary

If the workers are CPU-saturated in both arms of a comparison, then `rps × cycles-per-request` should be roughly constant between them — it is just total cycles per second across the same worker count. That check passes for three of the four 4-worker cells and fails badly for one: **12KB + TLS**. The published 36% penalty for that cell may be substantially load-generator artifact rather than server cost.

## The arithmetic

| cell | rps | cycles/req | rps × cycles |
|---|---:|---:|---:|
| 500B plaintext | 856,000 | 20,027 | 17.14 Gcyc/s |
| 500B TLS | 778,000 | ~21,800 | 16.96 Gcyc/s |
| 12KB plaintext | 802,000 | 21,138 | 16.95 Gcyc/s |
| **12KB TLS** | **512,000** | **26,166** | **13.40 Gcyc/s** |

Three cells agree within 1%. The fourth is **21% low**. Put differently: +23.8% cycles/request against the 12KB plaintext baseline predicts **648k rps**, but the harness reports **512k**. Decomposing the published 36.2%:

- 802k → 648k (**19.2%**) — consistent with the measured per-request cycle cost
- 648k → 512k (a further **21%**) — unaccounted for; consistent with workers not being saturated

## Caveat on the above, stated plainly

The `cycles/req` figures come from `ab2.py` on the **macOS host** via `proc_pid_rusage`; the rps figures come from the **Docker Linux aarch64** harness (`provenance.os` = `Linux 7.0.12-linuxkit`). Mixing them is not rigorous.

But mixing them cannot be the *explanation*, because a units/platform mismatch would distort all four cells in roughly the same direction, and three of them reconcile. So there is something specific to 12KB + TLS. This should still be re-measured with both numbers from the same platform before anyone acts on the decomposition.

## Leading hypothesis: the load generator

`bench/compare/harness.py` sets no `taskset` or cpuset, so `wrk` and the workers compete for the same CPUs. At 512k rps × 12KB, **`wrk` has to AES-GCM-decrypt about 6.3 GB/s** — and it does that across only 4 threads. Supporting detail: three of the four 4-worker cells land near ~200k rps per wrk thread; the 12KB TLS cell is the only one well below, at ~128k.

Secondary factor: with `-c40` and no pipelining, throughput is bounded by `concurrency ÷ round-trip latency` (Little's Law). At 802k rps each request must complete in 49.9 µs end-to-end; at 512k, 78.1 µs. Latency added *anywhere in the loop*, including inside `wrk`, caps throughput regardless of how idle the server is.

## Actions

1. **Re-run the 12KB TLS cell with `-t8 -c200`.** If throughput moves toward 648k, a meaningful share of the headline 36% is measurement.
2. **Pin `wrk` and the workers to disjoint CPU sets** and re-run. This is the cleaner experiment; (1) is the cheaper one.
3. **Pin the cipher suite on both ends.** `ctx.server_cipher_preference` is never set in `freastal/src/tls.c`, so picotls takes the *client's* first match — and `wrk` links OpenSSL, whose default TLS 1.3 order is AES-256-GCM first. So the benchmark measures AES-256-GCM while Chrome, Firefox and Safari all offer AES-128-GCM first and would get it. On this host that costs ~nothing (measured: AES-128-GCM 8584 MB/s vs AES-256-GCM 8525 MB/s at 16KB blocks, three runs, 0.7% apart — inside the ~3% run-to-run spread), but on a Neoverse N1 target (Graviton 2, Ampere Altra) the gap should be ~30%, so the harness would silently measure something browsers never negotiate. Pin it explicitly and note why.

   Precedent for how badly this can mislead: [netty/netty#7957](https://redirect.github.com/netty/netty/issues/7957) was a large-body TLS "regression" that turned out to be JDK negotiating AES-128-CBC while OpenSSL negotiated AES-128-GCM. Pinning the cipher made it vanish entirely.
4. **Record per-process CPU alongside rps** in `results.json`. If the harness reported worker CPU utilization per cell, this whole question would have been answerable from the existing output rather than by inference. That is probably the most durable fix.

## Why this matters before other work

Items #31, #35 and #37 are all competing for what is, on the current accounting, a ~0.3 µs fixed per-request cost. If ~21% of the 12KB TLS cell is client contention, the real server-side target is 19% rather than 36%, and the sizing of every proposed optimization changes. Worth resolving first — it costs one or two runs.

## Context for interpreting the result

Converting out of percentages: freastal's TLS cost at 12KB is **+2.82 µs/request**. For scale, Go's `net/http` measured on the same CPU class with a 12KB dynamic body, TLS 1.3, keepalive, loopback came to **+3.00 µs/request** (57.96 → 60.97 µs server CPU). Go reports that as −3.9% and freastal reports −36.2% purely because Go's baseline is 58 µs and freastal's is 5 µs. A fast plaintext path inflates the ratio. Roughly 60% of freastal's 2.82 µs is AES-GCM at hardware rate (12,418 bytes at ~7.3-8.5 GB/s ≈ 1.5-1.7 µs), which is irreducible.

## Comments

**jbylund** (2026-09-03T01:41:14Z):

Overlaps with #34, which was filed in parallel and proposes the stronger version of action (2): running the server and load generator in **separate containers** with an explicit 1500 MTU, rather than pinning them to disjoint CPU sets on one host.

If #34 lands, it supersedes actions (1) and (2) here — a separate container removes the CPU contention that is the leading hypothesis for the missing 21%, and the MTU change removes loopback's oversized-segment artifact at the same time.

What stays specific to this issue either way:

- **Action (3)**, pinning the cipher suite on both ends, so the harness stops measuring AES-256-GCM while browsers negotiate AES-128-GCM.
- **Action (4)**, recording per-process worker CPU next to rps in `results.json`, which is what would have made this question answerable from the existing output instead of by inference.
- The reconciliation check itself, which should be re-run after #34 to confirm the 12KB TLS cell comes back into line with the other three.

