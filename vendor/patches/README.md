# Local picotls patches

`vendor/picotls` is a derived tree, not a hand-maintained fork. What is committed
is picotls at `vendor/picotls/UPSTREAM_COMMIT`, with every patch in this
directory applied in filename order — and nothing else. `scripts/vendor_picotls.sh`
is what derives it, and CI runs `--check` on any change under `vendor/` to keep
that claim true.

## Working on the vendored copy

```bash
scripts/vendor_picotls.sh --check          # tree == upstream + these patches?
scripts/vendor_picotls.sh                  # rebuild the tree from upstream + patches
scripts/vendor_picotls.sh --pin <sha>      # move the pin and rebuild
```

Editing `vendor/picotls` directly is the one thing not to do: `--check` turns red,
and the next sync silently discards the edit. To change picotls:

1. Edit `vendor/picotls` anyway, to get the change working.
2. `git diff --relative=vendor/picotls -- vendor/picotls > vendor/patches/NNNN-name.patch`,
   and write a commit-message-style header above the diff saying *why*.
3. `scripts/vendor_picotls.sh --check` to confirm the patch reproduces the tree.

## Patch format

Paths inside a patch are relative to the picotls root (`a/lib/picotls.c`), which
is deliberate: it is also how they are relative to a picotls checkout, so a patch
here can be sent upstream with `git apply` and no path surgery. Write the picotls
side in upstream's style — `.clang-format` at the picotls repo root, 132 columns —
not freastal's.

## Syncing to a newer upstream

`--pin <sha>` fetches that commit, rebuilds, and stops with the reject output if a
patch no longer applies. It writes nothing on failure, so the tree and the pin stay
as they were until the patch is rebased or dropped. Drop a patch outright once
upstream carries the change.

## Current patches

- `0001-add-ptls_send_v.patch` — `ptls_send_v()`, a vectored `ptls_send()`. Lets
  freastal encrypt a response header and body into one TLS record without first
  copying them into one buffer. Upstream has no equivalent; see
  [envoyproxy/envoy#17219](https://github.com/envoyproxy/envoy/issues/17219) for
  the same capability being asked of BoringSSL one layer up.

## Files that are not upstream's

Two files under `vendor/picotls` are freastal's own and are never touched by a
sync: `include/picotls-probes.h` (upstream generates it from `picotls-probes.d`
with dtrace) and `lib/wincompat.h` (upstream keeps it under `picotlsvs/` for the
MSVC build). Both are stubs here.
