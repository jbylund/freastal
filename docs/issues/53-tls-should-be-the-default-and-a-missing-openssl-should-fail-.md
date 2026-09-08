# #53: TLS should be the default, and a missing OpenSSL should fail the build rather than silently disabling it

- **Original URL:** https://github.com/jbylund/freastal/issues/53
- **Author:** jbylund
- **Created:** 2026-09-03T16:41:20Z
- **Labels:** enhancement

## Summary

`setup.py` decides whether to build TLS by sniffing for OpenSSL headers, and quietly builds without
it when the sniff fails. A machine where OpenSSL is installed somewhere unexpected produces a
TLS-less freastal that nobody asked for. Building without TLS is a legitimate configuration — it
should just be one you *choose*, not one you get by accident.

Follow-up to #51, which fixed the worst consequence (a `certfile` on such a build served plaintext)
and added the pieces this needs.

## Current behaviour

```python
has_openssl = bool(ssl_inc) or any(
    os.path.exists(os.path.join(d, "openssl", "ssl.h"))
    for d in ["/usr/include", "/usr/local/include", "/opt/homebrew/include"]
)
```

A pkg-config probe, then three hardcoded directories. Miss all four and TLS is dropped. Three
things are wrong with that as a *default*:

1. **The failure is invisible in practice.** The build does print
   `freastal: OpenSSL not found – TLS 1.3 DISABLED`, but `pip install` hides build output unless
   the build fails or `-v` is passed. A message pip swallows is not a warning — and it is arguably
   worse than silence, because it makes the case look handled.
2. **Header presence is not the capability.** There is no link check. OpenSSL headers without a
   usable `libssl`/`libcrypto` still report TLS as available, and the failure moves to link time or
   later. This is the same shape as the `UV_TCP_REUSEPORT` enum probe in #49: a compile-time proxy
   standing in for the real question.
3. **The directory list goes stale.** Anything outside those three paths — a non-standard prefix, a
   cross-compile sysroot, a Nix or Conda environment, a non-Homebrew macOS install — silently loses
   TLS.

## Why a TLS-less build is still worth supporting

Not arguing for removing it. There are real reasons to want one:

- **TLS terminated upstream.** nginx, Envoy, an ALB, Cloudflare, or a mesh sidecar terminates and
  the app server speaks plaintext on loopback. This is a mainstream deployment, and there OpenSSL
  is pure cost: another system dependency to patch, more attack surface, and ~11k lines of vendored
  crypto-adjacent C compiled for nothing. The benchmark table in the README shows TLS costs
  throughput, so these users have a concrete motive.
- **OpenSSL genuinely absent** — Alpine/musl without `openssl-dev`, minimal containers, some
  cross-compile targets.
- **Build cost.** `scripts/build_vendor.sh` exists precisely because compiling picotls once per arch
  rather than per Python version was worth the trouble.

Worth stating plainly, since it is easy to assume otherwise: **vendoring picotls does not make TLS
self-contained.** `vendor/picotls/lib/` ships `openssl.c` and no other backend — upstream's
`minicrypto.c`, `cifra/` and `fusion.c` are not vendored. So the vendored tree provides the TLS
*protocol* and takes its *cryptography* from OpenSSL. "Build without TLS" means "build without
OpenSSL".

## Proposal

Invert the default so the choice is explicit:

- **Default:** build TLS. If OpenSSL cannot be found, **fail the build** with a message naming what
  to install and how to opt out.
- **Opt out:** `FREASTAL_NO_TLS=1`, which #51 already added and which the `Build without OpenSSL`
  CI job already exercises.

Roughly:

```
error: freastal: OpenSSL development headers not found, so TLS 1.3 cannot be built.

  Debian/Ubuntu:  apt install libssl-dev
  Fedora/RHEL:    dnf install openssl-devel
  macOS:          brew install openssl@3
  Alpine:         apk add openssl-dev

If you do not want TLS -- for example because TLS is terminated by a proxy in
front of freastal -- build with FREASTAL_NO_TLS=1 to opt out deliberately.
```

Also worth doing while in here: make the probe answer the real question by attempting a compile and
link of a trivial OpenSSL program, rather than looking for a header in three directories.

## The tradeoff

`pip install freastal` currently succeeds on a machine without OpenSSL headers and would then fail.
That is a real regression for anyone who does not care about TLS and never noticed they were not
getting it.

Argued for anyway: wheels published to PyPI cover the common platforms, so source builds are the
minority path; the failure is loud, immediate, and tells you exactly what to run; and the escape
hatch is one environment variable. The alternative is what we have — an install that silently does
less than it says on the tin, which is the failure mode #51 was filed about.

## Already in place

- `freastal.has_tls` reports what the build can do (#51)
- `FREASTAL_NO_TLS=1` forces the TLS-less build (#51)
- A `Build without OpenSSL` CI job compiles that configuration and asserts a certfile is refused
  rather than downgraded (#51)

So this issue is a change of build **policy** and messaging. The runtime pieces it depends on have
landed.

## Not verified

Whether any currently-supported install path actually relies on the silent fallback — i.e. whether
anyone is building from sdist on a machine without OpenSSL today and would be broken by this. Worth
checking before shipping.

