#!/usr/bin/env bash
# Rebuild vendor/picotls from upstream at the pinned commit, then re-apply the
# local patches in vendor/patches/.
#
#   scripts/vendor_picotls.sh                re-vendor in place; review with `git diff`
#   scripts/vendor_picotls.sh --check        assert the committed tree == upstream + patches
#   scripts/vendor_picotls.sh --pin <sha>    move UPSTREAM_COMMIT to <sha> and re-vendor
#
# vendor/picotls is a *derived* tree: nothing under it is edited by hand.  A
# local change to picotls is a patch file, and what is committed is upstream at
# UPSTREAM_COMMIT with those patches applied.  That is the whole point -- a
# sync becomes "--pin the new sha, fix whatever fails to apply, commit", and
# --check in CI keeps the derivation honest in between, so nobody can quietly
# hand-edit the vendored copy and strand the patch.
#
# The patches carry picotls-relative paths (a/lib/picotls.c), which is both how
# they apply here and how they would apply to a picotls checkout -- so a patch
# can be sent upstream as-is.
set -euo pipefail

# A CDPATH inherited from the user's shell makes `cd` echo where it went, which
# would end up inside the command substitutions below.
CDPATH=""

REPO_URL="${PICOTLS_REPO:-https://github.com/h2o/picotls.git}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR="$ROOT/vendor/picotls"
PATCH_DIR="$ROOT/vendor/patches"
PIN="$VENDOR/UPSTREAM_COMMIT"

# Taken verbatim from upstream.  freastal builds picotls.c, openssl.c,
# pembase64.c, hpke.c and asn1.c (see setup.py); the rest are headers those
# five include.
FILES=(
    include/picotls.h
    include/picotls/asn1.h
    include/picotls/certificate_compression.h
    include/picotls/minicrypto.h
    include/picotls/openssl.h
    include/picotls/pembase64.h
    lib/asn1.c
    lib/certificate_compression.c
    lib/chacha20poly1305.h
    lib/hpke.c
    lib/openssl.c
    lib/pembase64.c
    lib/picotls.c
    lib/quiclb-impl.h
)

# freastal's own, not upstream's, and so never overwritten by a sync: upstream
# generates picotls-probes.h from picotls-probes.d with dtrace and keeps
# wincompat.h under picotlsvs/ for the MSVC build.  freastal wants neither, so
# both are one-line stubs committed under vendor/picotls.
STUBS=(
    include/picotls-probes.h
    lib/wincompat.h
)

mode=sync
new_pin=""
while [ $# -gt 0 ]; do
    case "$1" in
        --check) mode=check ;;
        --pin)   new_pin="${2:?--pin needs a commit sha}"; shift ;;
        -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
if [ -n "$new_pin" ] && [ "$mode" = check ]; then
    echo "--pin and --check do not go together" >&2
    exit 2
fi

commit="${new_pin:-$(sed -n 's/^COMMIT=//p' "$PIN")}"
[ -n "$commit" ] || { echo "no COMMIT= in $PIN" >&2; exit 1; }
echo "picotls upstream: $commit"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A shallow fetch of the one commit; picotls is not small and no sync needs its
# history.
git init -q "$work/src"
git -C "$work/src" remote add origin "$REPO_URL"
git -C "$work/src" fetch -q --depth 1 origin "$commit"
git -C "$work/src" checkout -q FETCH_HEAD

# Both modes build the tree from scratch in $stage; only the last step differs.
# Staging outside vendor/ is not just tidiness: `git apply` resolves the paths
# in a patch against the enclosing repository when there is one, so applying
# these picotls-relative patches with the cwd inside freastal's checkout
# quietly matches nothing and still exits 0.
stage="$work/picotls"
mkdir -p "$stage"
if (cd "$stage" && git rev-parse --show-toplevel) >/dev/null 2>&1; then
    echo "staging dir $stage is inside a git repository; point TMPDIR elsewhere" >&2
    exit 1
fi

for f in "${FILES[@]}"; do
    mkdir -p "$stage/$(dirname "$f")"
    cp "$work/src/$f" "$stage/$f"
done
for f in "${STUBS[@]}"; do
    mkdir -p "$stage/$(dirname "$f")"
    cp "$VENDOR/$f" "$stage/$f"
done
printf 'COMMIT=%s\n' "$commit" > "$stage/UPSTREAM_COMMIT"

shopt -s nullglob
for p in "$PATCH_DIR"/*.patch; do
    echo "applying $(basename "$p")"
    if ! (cd "$stage" && git apply -p1 --whitespace=nowarn "$p"); then
        echo "" >&2
        echo "$(basename "$p") does not apply to picotls $commit." >&2
        echo "Rebase it against upstream, or drop it if upstream took the change." >&2
        exit 1
    fi
done

if [ "$mode" = check ]; then
    if diff -ru "$stage" "$VENDOR"; then
        echo "vendor/picotls matches picotls $commit + vendor/patches"
    else
        echo "" >&2
        echo "vendor/picotls is NOT picotls $commit + vendor/patches (diff above)." >&2
        echo "Either move the change into a patch file, or re-run without --check." >&2
        exit 1
    fi
else
    # Replace rather than overlay, so a file upstream deleted -- or one someone
    # dropped in by hand -- does not survive the sync.
    rm -rf "$VENDOR"
    cp -R "$stage" "$VENDOR"
    echo "vendor/picotls rebuilt; review with: git diff -- vendor/picotls"
fi
