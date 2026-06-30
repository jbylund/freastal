#!/usr/bin/env bash
# Compile picotls + picohttpparser into a static archive once per arch so
# cibuildwheel can reuse the objects across all Python versions instead of
# recompiling ~11k lines of C for every wheel.
#
# Output: /tmp/freastal_vendor.a
# Called from [tool.cibuildwheel.linux] before-all in pyproject.toml.
set -euo pipefail

CC="${CC:-cc}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT="/tmp/freastal_vendor.a"

# Locate OpenSSL headers via pkg-config (installed by dnf in before-all).
if command -v pkg-config &>/dev/null && pkg-config --exists openssl 2>/dev/null; then
    OPENSSL_CFLAGS=$(pkg-config --cflags openssl)
else
    OPENSSL_CFLAGS=""
fi

BASE_CFLAGS="-O3 -fPIC -I$ROOT/vendor/picotls/include -I$ROOT/vendor/picotls/lib $OPENSSL_CFLAGS"

TMPDIR_OBJ=$(mktemp -d)
trap 'rm -rf "$TMPDIR_OBJ"' EXIT

OBJECTS=()
for src in \
    "$ROOT/vendor/picohttpparser/picohttpparser.c" \
    "$ROOT/vendor/picotls/lib/picotls.c" \
    "$ROOT/vendor/picotls/lib/openssl.c" \
    "$ROOT/vendor/picotls/lib/pembase64.c" \
    "$ROOT/vendor/picotls/lib/hpke.c" \
    "$ROOT/vendor/picotls/lib/asn1.c"
do
    obj="$TMPDIR_OBJ/$(basename "$src" .c).o"
    # shellcheck disable=SC2086
    "$CC" $BASE_CFLAGS -c "$src" -o "$obj"
    OBJECTS+=("$obj")
done

ar rcs "$OUT" "${OBJECTS[@]}"
echo "freastal: built vendor archive $OUT ($(du -sh "$OUT" | cut -f1))"
