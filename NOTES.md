# Issue #29 — TLS session resumption, with a rotation story

Branch `issue29/b2`, one commit `484176a` on top of `51de6b7`. Not pushed, no PR.

## What changed

| file:line | what |
| --- | --- |
| `freastal/src/server.h:159-233` | Ticket-key constants, the `LIFETIME <= (RING-1)*ROTATE` static assert, `tls_ticket_key_t`, and four new fields on `tls_server_t` (`ticket_cb`, `ticket_keys[3]`, `ticket_cur`, `ticket_timer`) |
| `freastal/src/tls.c:6-12` | `core_names.h`/`params.h` on OpenSSL 3, `hmac.h` otherwise |
| `freastal/src/tls.c:59-229` | The ticket block: version-split MAC init, `tls_ticket_key_mint`, `tls_ticket_key_by_name`, `tls_ticket_key_cb`, `tls_ticket_encrypt`, `tls_ticket_rotate`, and the "Multiple workers" note |
| `freastal/src/tls.c:278-343` | Wiring in `tls_server_init`: mint key 0, `encrypt_ticket`, `ticket_lifetime`, `require_dhe_on_psk`, `uv_timer_init`/`uv_unref`/`uv_timer_start` |
| `tests/test_tls.py:970` | The strict xfail marker deleted |
| `tests/test_tls.py:995-1046` | Two new tests |
| `README.md:124-128` | User-visible behaviour: lifetime, rotation, no 0-RTT, per-worker key |

## The numbers, and why

**LIFETIME = 2h, ROTATE = 1h, RING = 3.**

These are one constraint, not three knobs. A key becomes current at `t0`, stops
sealing at `t0+ROTATE`, so the last ticket under it is accepted until
`t0+ROTATE+LIFETIME`; its slot is reused — and the key destroyed — at
`t0+RING*ROTATE`. For no client to be told "resume with this" and then handed a
full handshake inside the lifetime it was promised:

```
LIFETIME <= (RING - 1) * ROTATE
```

`2h <= 2 * 1h` — tight, and asserted at compile time (`server.h:210`).

Rearranged, the constraint *fixes* the exposure window given a lifetime: the
oldest key in the ring is `RING*ROTATE = LIFETIME * RING/(RING-1)` old. So the
window can never be shorter than LIFETIME itself, and RING only picks the
multiple — 2x at RING=2, **1.5x at RING=3**, 1.25x at RING=5. RING=3 takes most
of the drop for 243 bytes and one timer an hour; RING=5 would halve the rotation
period to shave a further 0.25x. Result: an attacker who takes the process at
time T can open tickets sealed back to T-3h. Today it is every ticket since
boot — an uptime-of-the-process window, which on a long-lived server is weeks.

**Why 2h and not the 24h the issue calls typical.** The exposure window is a
fixed multiple of the lifetime, so 24h buys 36h of exposure. What it buys back
is the far tail of the return-visit distribution: the workload resumption
actually serves — a user returning to a tab, a dropped connection reopened, a
client that does not pool — is minutes to a couple of hours. 2h is also exactly
OpenSSL's own default session timeout, so a stock OpenSSL client's own cache
expires at the same moment ours does and the two never disagree; and it is well
inside RFC 8446 4.6.1's 604800s ceiling.

**`require_dhe_on_psk = 1`** is the other half of the forward-secrecy story and
the issue does not mention it. Left at 0, picotls picks `HANDSHAKE_MODE_PSK`
whenever the client offers `psk_ke` (`vendor/picotls/lib/picotls.c:4800`), and
the resumed session's traffic keys derive from the ticket secret alone —
so a recorded session is decryptable by anyone who later gets the ticket key,
and no amount of rotation helps sessions already on the wire. With it set, the
resumed handshake still runs a fresh ECDHE and a stolen ticket key yields the
resumption secret and no plaintext. It bounds *impersonation* to the ticket
window, which is what a bounded key lifetime can actually deliver.

**Where the timer lives, and locking.** `uv_timer_t` on `g_server.loop`, started
in `tls_server_init` (the loop is assigned at `server.c:521`, TLS init runs at
`:547`). No lock, and none needed: a freastal worker is a *process* — the C has
no `pthread_create`/`uv_thread` at all, and `freastal/__init__.py` uses
`multiprocessing.Process` — with one libuv loop on one thread, so libuv
serialises the rotation callback against the handshake callbacks that read the
ring. The handle is `uv_unref`'d so an hourly repeating timer is never the
reason `uv_run` will not return.

**Zeroization.** `tls_ticket_rotate` calls `ptls_clear_memory` on the slot before
minting into it. That is a `volatile` function pointer
(`picotls.h:1946`, statically initialised at `picotls.c:6669`), so the compiler
cannot drop the write as dead — which it would be entitled to do to a plain
`memset` of a struct written again on the next line. The `live` flag is
load-bearing rather than bookkeeping: a zeroized slot's name is sixteen zero
bytes under an all-zero key, all of which an attacker knows, so matching one
would let anybody forge a ticket.

## Verified

**xfail → pass.** With the implementation in and the marker still present:

```
$ .venv/bin/python -m pytest tests/test_tls.py -q -k session_ticket
FAILED tests/test_tls.py::test_session_ticket_is_issued_and_resumes[wsgi] - [XPASS(strict)]
FAILED tests/test_tls.py::test_session_ticket_is_issued_and_resumes[asgi] - [XPASS(strict)]
2 failed, 93 deselected
```

**Full suite.** Baseline at `51de6b7` (`git stash`, rebuild, run):
`338 passed, 3 skipped, 2 xfailed in 14.24s`. After: `344 passed, 3 skipped in
14.82s` — the 2 xfails became passes and 2 new tests × the wsgi/asgi fixture
params added 4. Lint: `25 files already formatted` + `ruff check` clean (ruff
0.16.5). `scripts/vendor_picotls.sh --check`: *"vendor/picotls matches picotls
a06ca41 + vendor/patches"* — no picotls change was needed.

**The static assert really fires.** Bumping LIFETIME to 3h:

```
server.h:210:16: error: static assertion failed due to requirement
'(unsigned long long)(3U * 60U * 60U) * 1000U <= (unsigned long long)(3 - 1) * (60U * 60U * 1000U)':
a ticket would outlive the key that can open it: clients would be handed a
surprise full handshake inside ticket_lifetime
```

**Rotation actually rotates, and a retired key still unseals.** A throwaway build
with `ROTATE_MS=1000, LIFETIME_S=2, RING=3` (constraint still satisfied), one
ticket taken at t=0 and re-offered on later connections:

```
t=+0.00s  issued ticket, hint=2s
t=+0.21s  resumed=True   request_ok=True
t=+1.44s  resumed=True   request_ok=True     <- one rotation has happened
t=+1.92s  resumed=True   request_ok=True     <- still opened by the retired key
t=+2.40s  resumed=False  request_ok=True     <- picotls' own age check
t=+3.53s  resumed=False  request_ok=True
```

**The constraint is not decorative.** Same build with the assert disabled and
`LIFETIME_S=30` (so `30s > (3-1)*1s`):

```
t=+0.00s  issued ticket, hint=30s
t=+0.22s  resumed=True   request_ok=True
t=+1.55s  resumed=True   request_ok=True
t=+2.50s  resumed=True   request_ok=True
t=+3.51s  resumed=False  request_ok=True     <- key destroyed at RING*ROTATE = 3s
t=+5.02s  resumed=False  request_ok=True
```

The client was promised 30 seconds and got 3. The cliff is exactly `RING*ROTATE`.
That is the "surprise full handshake" the assert exists to prevent.

**Resumption is psk_dhe_ke.** The ServerHello is in the clear, so its extension
list can be read off a memory-BIO capture without decrypting anything:

```
full     : reused=False  ServerHello exts=[43, 51]        (supported_versions, key_share)
resumed  : reused=True   ServerHello exts=[43, 51, 41]    (+ pre_shared_key)
```

`key_share` present alongside `pre_shared_key` means a fresh ECDHE ran on the
resumed handshake.

**What resumption is worth here.** Self-signed RSA-2048, loopback, 200 sequential
connect/request/close cycles, best of 3:

```
server handshake bytes: full=2608  resumed=1512      (-42%)
full   : 200 sequential connections in 168 ms (0.84 ms each)
resumed: 200 sequential connections in  76 ms (0.38 ms each)   (-55%)
```

The byte count is deterministic. The timing is loopback wall-clock over the whole
cycle, not isolated server CPU, so read it as an order of magnitude, not a
benchmark row — the issue is right that a proper connection-churn row belongs in
`bench/`, and I did not add one.

## Multi-worker

**Not shared. Per-process ring, documented, with a test for the failure mode.**

The brief's phase-1 finding holds: the issue's "inherited across the fork" is
wrong here. `freastal/__init__.py:71` uses `multiprocessing.Process`, whose
default start method is `spawn` on macOS — the child re-imports and re-runs
`tls_server_init()` in a fresh interpreter with nothing inherited. On Linux the
default is fork, so that design would work on one platform and silently not on
the other, which is worse than not having it.

I considered and rejected two ways to share it:

- **Pass the key through the spawn pickle.** Works on both start methods, but puts
  key material in immutable Python `bytes` that cannot be zeroized, may be copied
  by the GC and may be paged out. And it shares only the *initial* key —
  rotation would then need cross-process coordination anyway.
- **One master secret per deployment, per-epoch keys derived from the wall clock.**
  Elegant (rotation needs no IPC at all), but it makes a single long-lived master
  the thing worth stealing, and every key past and future derives from it. That
  is precisely the forward secrecy this change is about, traded away to get the
  hit rate back.

Doing it properly means an operator-owned key rotated out of band, the way
nginx's `ssl_session_ticket_key` works. That is a deployment interface, not a
line of C, and it is not this issue.

Consequence, stated in the README: with `workers = N`, a resuming client lands on
the issuing worker about `1/N` of the time and otherwise offers a ticket nobody
holds the key for. That is a hit-rate shortfall, **not** a correctness failure —
returning 0 from the key callback makes picotls skip the PSK identity and do a
full handshake, which is exactly what every connection did before this change.
So `workers > 1` is no worse than today and `workers = 1` is strictly better.

`test_ticket_from_another_process_falls_back_to_a_full_handshake` pins that,
using a second server on its own port so the kernel's worker choice is out of it.

## Not covered

- **Actual multi-worker resumption.** Still zero coverage, as before. The new test
  covers the *miss* path deterministically; it does not start `workers=2`.
- **Rotation at the shipped period.** Nothing in the suite waits an hour. Rotation
  was verified only on the shrunk-constant builds above; the shipped constants are
  covered by the static assert and by the two tests that exercise seal/unseal
  under key 0.
- **`require_dhe_on_psk` making a difference in the suite.** I flipped it back to 0
  and re-ran the ServerHello capture: still `[43, 51, 41]`. OpenSSL clients only
  ever offer `psk_dhe_ke`, so with a Python-`ssl` client the flag is a no-op and
  no test I can write here distinguishes the two settings. It is defence against
  a client that *does* offer `psk_ke` — I am asserting the code path from reading
  `picotls.c:4572` and `:4800`, not from observing it.
- **The legacy `HMAC_CTX` branch is compiled by nobody I ran.** This machine and
  both CI legs are OpenSSL 3.x, so `tls.c`'s `#else` (LibreSSL, OpenSSL < 3.0)
  is written from picotls' header and never built. It exists because naming
  `ptls_openssl_encrypt_ticket_evp` unconditionally would not *degrade* on an
  older OpenSSL, it would fail to link — but it is unexercised code.
- **Ticket-flood DoS.** A peer can offer many PSK identities and make us do a key
  lookup (three memcmps) and, on a name hit, an HMAC. Far cheaper than the RSA
  signature it replaces, so I did not add a limit — but I did not measure it.
- **A second call to `tls_server_init()` in one process.** It opens with
  `memset(ts, 0, sizeof(*ts))`, which now covers a `uv_timer_t` the loop already
  has in its handle queue — so a second call would corrupt that queue rather than
  merely re-initialising a struct. It is unreachable (`serve()` blocks in
  `uv_run` forever, and the multi-worker parent never calls `_serve_single`), and
  the pre-existing `uv_tcp_init(g_server.loop, &g_server.handle)` has the same
  shape, so I left it. Worth knowing that this change sharpened an existing
  edge from "wrong" to "memory-unsafe".

## Tried and abandoned

- **Pre-filling the whole ring at startup.** My first shape minted all three keys
  up front and just advanced `ticket_cur`. It is strictly worse: the key at index
  1 is minted at t=0, does not seal until t=1h, and is not destroyed until
  t=4h — four hours of exposure for a key that sealed one hour of tickets.
  Lazy minting, one fresh key per rotation, makes every key's life exactly
  `RING*ROTATE`.
- **Isolating "key destroyed" from "ticket expired" in a shipped test.** Impossible
  by construction: the constraint the code enforces guarantees the age check
  always fires first. Demonstrating key destruction required deliberately
  violating the assert, which is why that experiment is in this file rather than
  in `tests/`.
- **A byte-count assertion on the handshake in the test suite.** The 2608→1512
  figure depends on the certificate the fixture generates, so it would pin the
  fixture, not the feature. Left as a measurement here.

## The decision I am least sure about

**LIFETIME = 2h.** The constraint arithmetic and everything downstream of it I am
confident in; the absolute number is a judgement about a return-visit
distribution I have not measured for this server. If real traffic shows a fat
band of returns between 2 and 24 hours, 2h leaves hits on the table, and the
honest fix is to raise LIFETIME *and* RING together (LIFETIME=6h needs
ROTATE=1h with RING=7, keeping exposure at 7h rather than the 9h that RING=3
would force). The shape of the change is a one-line edit that the static assert
will refuse if you get it wrong; the number itself is the guess.

A close second: **the per-worker ring**. It is the conservative call and I stand
by the reasoning, but the practical effect is that `workers=4` — which is what
the README's own TLS example shows — gets a quarter of the win. Someone could
reasonably argue that shipping the spawn-pickle version, ugly as the key handling
is, beats shipping 25% of the feature for the common deployment.

## Where the issue and the tree disagree

1. **"inherited across the fork"** — wrong on macOS (`spawn`). See above.
2. **The `_evp` pair is the only option named** — the tree also has the legacy
   `HMAC_CTX` pair at `vendor/picotls/include/picotls/openssl.h:236`, unguarded,
   which is what OpenSSL < 3.0 and LibreSSL need.
3. **Not wrong, just missing: `require_dhe_on_psk`.** The issue asks for a
   rotation story for forward secrecy but does not mention that without this flag
   a resumed session can have no forward secrecy at all, which no rotation period
   would fix.
