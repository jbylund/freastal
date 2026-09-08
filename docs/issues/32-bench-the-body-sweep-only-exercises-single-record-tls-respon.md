# #32: bench: the body sweep only exercises single-record TLS responses

- **Original URL:** https://github.com/jbylund/freastal/issues/32
- **Author:** jbylund
- **Created:** 2026-09-03T01:38:04Z
- **Labels:** enhancement

## Summary

`bench/compare/harness.py:345` defaults to:

```python
p.add_argument("--bodies", default="500,12000")
```

Both fit in a **single** TLS record and a **single** pooled encryption block, so the benchmark never measures the multi-record path, the malloc fallback (#31), or a pool miss. Those are exactly the paths where comparable projects found their wins.

## Evidence

`tls_encrypted_size()` (`freastal/src/server.c:635`) plus the pool decision at `server.c:676`, with `TLS_WBUF_SIZE = 16384 + 512 = 16896` (`server.h:22`) and a 92-byte bench response header:

| body | `need` | path taken |
|---|---:|---|
| 500 | 650 | pooled, 1 record |
| **12000** | **12136** | **pooled, 2 records** |
| 16384 | 16542 | pooled |
| 16738 | 16896 | pooled (exactly at the limit) |
| 16739 | 16897 | **malloc** |
| 65536 | 65760 | **malloc** |

The two benchmarked sizes cover one corner of the space. Not measured:

- bodies > 16384, which split into multiple TLS records
- bodies ≥ 16739, which hit `malloc(need)` **and** a `ptls_clear_memory()` over the whole ciphertext on release — see #31
- pool exhaustion under concurrency

This is a **benchmark** gap, not a test gap: `tests/test_tls.py` `BOUNDARY_SIZES` already straddles 16383/16384/16385/16895/16896/16897 and goes to 40000, so correctness is covered. Nothing *measures* those sizes.

## Why it matters

Every comparable project's optimization here was driven by large bodies, not small ones:

- **Envoy** [envoyproxy/envoy#2667](https://redirect.github.com/envoyproxy/envoy/issues/2667) — the report that produced its current 16KB linearize path was a **1 MB** request showing a 62% TLS penalty, against 33% at 0 bytes.
- **Netty** [netty/netty#13549](https://redirect.github.com/netty/netty/issues/13549) — a **5 MB** response doing ~320 allocations; the fix took it to "600+ → 2-3 allocations+releases".
- **Netty** [netty/netty#7957](https://redirect.github.com/netty/netty/issues/7957) — a large-body TLS regression at **5 MB and 20 MB** that turned out to be cipher negotiation rather than code. A cautionary tale for #33.

At 500B and 12000B freastal's write path is one pooled block and one `uv_write` either way, so the published table cannot distinguish it from a materially different design.

## Proposed change

Add larger sizes to the sweep:

```
--bodies 500,12000,65536,1048576
```

`run.sh` does not pass `--bodies` at all today, so this means either threading the flag through or changing the default. 65536 is the smallest size that is unambiguously multi-record and past the cliff; 1048576 matches the scale at which Envoy and Netty found their problems.

Costs: the run gets longer, and the 1 MB row will be bandwidth-bound on loopback rather than CPU-bound. That deserves a line in `bench/compare/README.md` under "Known gaps" so it is not misread as a CPU comparison.

## Acceptance

- `bench/compare/out/table.md` has at least one multi-record and one past-cliff row
- the top-level `README.md` table either includes them or says why not
- bandwidth-bound rows are labelled as such

## Related

- #31 is the code fix these rows would make visible; that issue is unmeasurable without this one.
- #30 proposes a **connection-churn** row — a different axis, exposing handshake cost (cert type, #28, #29) rather than the record/write path. Both are coverage gaps in the same harness and could reasonably share a PR.

## Comments

**jbylund** (2026-09-04T02:14:58Z):

## The evidence table above is stale: the malloc cliff moved from ~16.7KB to ~2MB

This issue was written when a response was encrypted into **one** pooled block, so anything past
`TLS_WBUF_SIZE` fell to `malloc`. #31 is now closed, and its fix — encrypting large responses into
a *chain* of pooled blocks, one vectored write (#40) — moved that boundary by two orders of
magnitude.

The decision today (`server.c:1184`):

```c
size_t nrec      = tls_record_count(total);
bool   oversized = unlikely(nrec > TLS_WSEG_MAX);
```

With `TLS_WSEG_MAX = 128` and `TLS_MAX_RECORD_PLAINTEXT = 16384`, the pooled chain covers
**2,097,152 bytes** before `tls_bigbuf_get()` is reached. So:

| body | this issue says | actually, today |
|---:|---|---|
| 16,739 | **malloc** | pooled, 2 records |
| 65,536 | **malloc** | pooled chain, 4 records |
| 1,048,576 | (proposed, to hit malloc) | pooled chain, 64 records — **never reaches malloc** |

Which means the proposed `--bodies 500,12000,65536,1048576` would **not** exercise the malloc
fallback at any size. Reaching it now needs a body over ~2MB, and #31 — the fix those rows existed
to make visible — is already merged, so the original motivation is largely spent.

## What is still true

The narrow claim holds: 500 and 12000 both fit in a **single** TLS record (12000 + a ~92-byte
header is 12092, under the 16384 plaintext cap), so the multi-record path is genuinely unmeasured
by the benchmark. That is a real gap, just a smaller one than this issue describes — and
correctness across it is already covered by `BOUNDARY_SIZES` in `tests/test_tls.py`.

## Suggested reduction

- Add **one** size, 65536, to the harness sweep. It is unambiguously multi-record (4 records, 4
  pooled blocks) and cheap to run.
- Keep it out of the top-level `README.md` table. That table is already 25 data rows across
  workers x TLS x body size x server x protocol; another body size doubles it for a path that
  differs from 12KB only by looping.
- Do **not** add a >2MB row. On loopback it is bandwidth-bound, so it measures the loopback path
  rather than freastal — and now that #55 records server CPU, such a row would show up as
  unsaturated, which is the honest reading and not a useful published number.

## Related, now that #31 is closed

#33 ("the 12KB TLS cell does not reconcile with per-request cycle cost") may be answerable with
#55's CPU columns rather than with more body sizes — a cell that does not reconcile is exactly what
a saturation figure is for.

