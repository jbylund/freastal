#!/usr/bin/env bash
#
# Regenerate the comparison table in README.md.
#
#   bench/compare/run.sh                    # full run, as published
#   bench/compare/run.sh --rounds 1 --duration 5   # smoke test
#
# Runs in a Linux container so the numbers describe a real epoll/SO_REUSEPORT
# platform.  On Apple Silicon the arm64 image is native, so this is a genuine
# ARM64 Linux measurement rather than emulation - but it is still a container
# on a shared desktop, and the recorded provenance says so.
#
# Results land in bench/compare/out/{results.json,table.md}.
set -euo pipefail

# An inherited CDPATH makes `cd relative/path` resolve somewhere else entirely
# and print where it went, which breaks command substitution.
unset CDPATH

HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO="$(cd -- "$HERE/../.." && pwd)"
IMAGE="${BENCH_IMAGE:-freastal-bench:latest}"
OUT="$HERE/out"

# The arch to measure. Native on the host's own arch; anything else is emulated
# and the numbers are meaningless, so we refuse rather than mislead.
PLATFORM="${BENCH_PLATFORM:-linux/$(uname -m | sed 's/^x86_64$/amd64/;s/^aarch64$/arm64/;s/^arm64$/arm64/')}"
HOST_ARCH="$(docker info --format '{{.Architecture}}' 2>/dev/null || echo unknown)"
case "$PLATFORM:$HOST_ARCH" in
  linux/arm64:aarch64|linux/arm64:arm64|linux/amd64:x86_64) ;;
  *) echo "refusing: $PLATFORM on a $HOST_ARCH host would be emulated." >&2
     echo "Set BENCH_PLATFORM explicitly only if you know it is native." >&2
     exit 1 ;;
esac

command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
mkdir -p "$OUT"

echo "==> building $IMAGE for $PLATFORM"
docker build --platform "$PLATFORM" -q -t "$IMAGE" -f "$HERE/Dockerfile" "$HERE" >/dev/null

COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if ! git -C "$REPO" diff --quiet 2>/dev/null; then
  COMMIT="$COMMIT-dirty"
fi
# The container has no view of the host CPU on a linuxkit VM, so read it here.
HOST_CPU="$(sysctl -n machdep.cpu.brand_string 2>/dev/null \
  || grep -m1 "^model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2- \
  || echo unknown)"
HOST_CPU="$(echo "$HOST_CPU" | sed "s/^ *//")"
echo "==> freastal $COMMIT on $HOST_CPU"

# Build the extension and run the benchmark in one container, so the .so being
# measured is provably the one built from the mounted tree on this platform.
docker run --rm --platform "$PLATFORM" \
  -v "$REPO:/src:ro" \
  -v "$OUT:/out" \
  -e "BENCH_FREASTAL_COMMIT=$COMMIT" \
  -e "BENCH_HOST_CPU=$HOST_CPU" \
  "$IMAGE" bash -euo pipefail -c '
    cp -r /src/freastal /src/vendor /src/setup.py /src/pyproject.toml /build 2>/dev/null \
      || { mkdir -p /build && cp -r /src/freastal /src/vendor /src/setup.py /src/pyproject.toml /build/; }
    cd /build
    rm -f freastal/*.so
    echo "==> building the freastal extension on $(uname -srm)"
    python setup.py -q build_ext --inplace 2>&1 | grep -Ei "error|warning: .*freastal/src" || true
    python -c "import freastal, sys; print(\"   freastal imports OK on\", sys.version.split()[0])"

    # Self-signed cert for the TLS row.
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
      -keyout /tmp/bench-key.pem -out /tmp/bench-cert.pem \
      -subj "/CN=localhost" >/dev/null 2>&1

    cp -r /src/bench/compare /work/compare
    cd /build
    PYTHONPATH=/build:/work/compare exec python /work/compare/harness.py "$@"
  ' -- "$@"

echo
echo "==> wrote $OUT/table.md and $OUT/results.json"
