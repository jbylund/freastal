# #30: bench: use an ECDSA P-256 cert instead of RSA-2048, and add a connection-churn row

- **Original URL:** https://github.com/jbylund/freastal/issues/30
- **Author:** jbylund
- **Created:** 2026-09-03T01:28:23Z
- **Labels:** enhancement

## Summary

Both the benchmark harness and the TLS tests mint an RSA-2048 self-signed certificate. Server-side RSA-2048 signing is roughly an order of magnitude more expensive than ECDSA P-256, and ECDSA is universally supported by browsers. The benchmark should use the certificate type a real deployment would.

## Locations

`bench/compare/run.sh:70`

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout /tmp/bench-key.pem -out /tmp/bench-cert.pem \
```

`tests/test_tls.py:82` uses `-newkey rsa:2048` in the same way.

## Fix

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -keyout /tmp/bench-key.pem -out /tmp/bench-cert.pem \
```

`ptls_openssl_init_sign_certificate` handles EC keys, so no server-side change is needed.

## Why it matters, and why the table will not move

The signature happens once per full handshake, and `wrk -t4 -c40` opens 40 connections and holds them for the whole 30s run — so the published numbers will not change. That is precisely the problem: the current TLS rows measure the record layer only and say nothing about handshake cost, while presenting themselves as "freastal with TLS."

Two separate changes, worth keeping distinct:

1. **This issue:** switch the cert to ECDSA P-256 so the benchmark reflects a realistic deployment.
2. **Follow-up:** add a connection-churn row to `bench/compare` — a mode where the load generator opens fresh connections rather than reusing them. That is the row where cert type, #28 (HelloRetryRequest) and #29 (no resumption) all become visible. Without it, every handshake-path regression is invisible to CI.

The second is the more valuable of the two and probably deserves its own issue once the shape is decided; noting it here so the connection is not lost.

