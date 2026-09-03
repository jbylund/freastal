# Image for the cross-server comparison benchmark.
#
# Everything is pinned, because the point of this harness is that the numbers
# in README.md can be regenerated and defended later.  Bumping a version here
# invalidates the recorded table; re-run rather than hand-edit.

FROM python:3.12-slim

ARG LIBUV_VERSION=1.52.1
ARG GUNICORN_VERSION=23.0.0
ARG UVICORN_VERSION=0.34.0
ARG UVICORN_WORKER_VERSION=0.3.0
ARG BJOERN_VERSION=3.2.2

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# build-essential/cmake: libuv and the freastal extension
# libssl-dev:            TLS 1.3 via the vendored picotls
# libev-dev:             bjoern's event loop
# wrk:                   the load generator (Debian ships 4.1.0)
RUN apt-get -qq update \
 && apt-get -qq install -y --no-install-recommends \
      build-essential cmake pkg-config curl ca-certificates \
      libssl-dev libev-dev wrk procps \
 && rm -rf /var/lib/apt/lists/*

# libuv from source at a pinned tag, so the number is not at the mercy of
# whatever the distro happens to ship.
RUN cd /tmp \
 && curl -sSL "https://github.com/libuv/libuv/archive/refs/tags/v${LIBUV_VERSION}.tar.gz" -o uv.tgz \
 && tar xzf uv.tgz && cd "libuv-${LIBUV_VERSION}" \
 && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
      -DCMAKE_INSTALL_PREFIX=/usr/local >/dev/null \
 && cmake --build build -j"$(nproc)" --target install >/dev/null \
 && ldconfig \
 && rm -rf /tmp/uv.tgz "/tmp/libuv-${LIBUV_VERSION}"

# uvicorn[standard] is deliberate: it pulls uvloop and httptools, which is what
# uvicorn's own deployment docs tell you to install. Bare `uvicorn` falls back
# to plain asyncio and the pure-Python h11 parser, which measured 87k rps here
# against 225k for the standard extras - i.e. benchmarking bare uvicorn is
# benchmarking a misconfiguration, not the competition.
#
# uvicorn-worker supplies the maintained gunicorn worker class; the one bundled
# in uvicorn itself is deprecated.
RUN pip install --no-cache-dir -q \
      setuptools wheel \
      "gunicorn==${GUNICORN_VERSION}" \
      "uvicorn[standard]==${UVICORN_VERSION}" \
      "uvicorn-worker==${UVICORN_WORKER_VERSION}" \
      "bjoern==${BJOERN_VERSION}"

# Recorded in the report so a table can be traced back to an image.
ENV BENCH_LIBUV_VERSION=${LIBUV_VERSION} \
    BENCH_UVICORN_WORKER_VERSION=${UVICORN_WORKER_VERSION} \
    BENCH_GUNICORN_VERSION=${GUNICORN_VERSION} \
    BENCH_UVICORN_VERSION=${UVICORN_VERSION} \
    BENCH_BJOERN_VERSION=${BJOERN_VERSION}

WORKDIR /work
