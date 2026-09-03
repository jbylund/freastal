# Shared brief: freastal issue #29 — TLS session resumption

Full issue text: `../issue29.md`. Read it, then read it critically — phase 1 of
this process already found two things it gets wrong. Where the issue and the
tree disagree, **the tree wins**; say so in your notes.

## The oracle already exists

PR #44 landed the acceptance criterion as a **strict xfail** in
`tests/test_tls.py:968`:

```python
@pytest.mark.xfail(strict=True, reason="#29: ctx.encrypt_ticket is NULL, ...")
def test_session_ticket_is_issued_and_resumes(tls_server):
```

It asserts a ticket is issued (`session.ticket_lifetime_hint > 0`) **and** that
offering it back actually resumes. Because it is `strict`, the moment your work
succeeds the suite goes RED with XPASS — that is the signal to delete the
marker. **Deleting the xfail marker is part of the job.** Do not weaken or
rewrite that test to suit your implementation.

## What phase 1 already established (do not re-derive; do verify)

- `tls_server_init()` (`freastal/src/tls.c:52`) sets `random_bytes`, `get_time`,
  `key_exchanges`, `cipher_suites`, `sign_certificate` and nothing else.
  `ctx.encrypt_ticket` and `ctx.ticket_lifetime` are indeed zero. Issue correct.
- `vendor/picotls/include/picotls/openssl.h:242` has
  `ptls_openssl_encrypt_ticket_evp` / `_decrypt_ticket_evp` — but behind
  `#if OPENSSL_VERSION_NUMBER >= 0x30000000L`. A **legacy `HMAC_CTX` pair**
  (`ptls_openssl_encrypt_ticket`, line ~235) exists for older OpenSSL. The issue
  mentions only the `_evp` pair. This machine has OpenSSL 3.6.3.
- **The issue's multi-worker fix is not portable.** It says the key must be
  "inherited across the fork". `freastal/__init__.py:70` spawns workers with
  `multiprocessing.Process`, and the default start method is **`spawn` on
  macOS** (confirmed) — there is no fork inheritance; the child re-imports and
  re-runs `tls_server_init()` in a fresh interpreter. On Linux the default is
  fork, so a fork-inheritance design silently works there and silently fails on
  macOS.
- The resumption test runs `workers=1` only. Multi-worker resumption has **zero
  test coverage** today.

## Ground rules

- Your worktree is yours alone; base commit is `origin/main` (51de6b7). Commit to
  your branch. **Do not push, do not open a PR, do not touch another worktree.**
- Build: `python3 -m venv .venv && .venv/bin/pip install -e . pytest httpx`.
  Header deps are tracked correctly as of `e99a901`, so a plain reinstall is
  enough; if you edit `vendor/` or hit anything odd, `rm -rf build` first.
- Test: `.venv/bin/python -m pytest tests/ -q`. Lint: `ruff format --check . &&
  ruff check .` (ruff 0.16.5).
- `vendor/picotls` is a **derived tree** as of #47: never hand-edit it. A change
  there is a patch in `vendor/patches/`, and `scripts/vendor_picotls.sh --check`
  (which CI runs) must still pass. You very likely need no picotls change at all.
- Style: this repo's C comments explain *why* and name the failure mode being
  avoided. Match it. Read surrounding code first.

## Hard constraints

- **0-RTT stays off.** `ctx.max_early_data_size` remains 0. Early data is
  replayable and a general-purpose WSGI/ASGI server cannot know whether the
  app's handlers are idempotent. Do not enable it, not even opt-in.
- Do not weaken the strict xfail test. Delete the marker when it passes.
- A ticket key is key material: think about its lifetime, where it lives, and
  whether it is zeroized. Do not log it.

## Deliverable

Commit, then write `NOTES.md` at the worktree root (uncommitted is fine):
- what changed, file:line
- what you verified, with actual command output (test counts; the xfail→pass
  transition; anything you measured)
- how you handled the multi-worker question, and what you did **not** cover
- anything you tried that failed, and why
- the one design decision you are least sure about

Be honest about what you did not verify. A smaller correct change beats a larger
speculative one.
