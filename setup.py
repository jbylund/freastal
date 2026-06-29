import os
import subprocess
from setuptools import Extension, setup

HERE = os.path.dirname(os.path.abspath(__file__))

def pkg_config(*args):
    try:
        out = subprocess.check_output(["pkg-config"] + list(args), stderr=subprocess.DEVNULL)
        return out.decode().split()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


# ---------- libuv (required) ----------

uv_includes = pkg_config("--cflags-only-I", "libuv")
uv_libs     = pkg_config("--libs-only-l",   "libuv")
uv_ldflags  = pkg_config("--libs-only-L",   "libuv")

include_dirs = [f[2:] for f in uv_includes if f.startswith("-I")]
library_dirs = [f[2:] for f in uv_ldflags  if f.startswith("-L")]
libraries    = [f[2:] for f in uv_libs      if f.startswith("-l")]

if not include_dirs:
    for candidate in ["/opt/homebrew/include", "/usr/local/include", "/usr/include"]:
        if os.path.exists(os.path.join(candidate, "uv.h")):
            include_dirs = [candidate]
            break

if not libraries:
    libraries = ["uv"]

# ---------- liburing (Linux-only, optional) ----------

define_macros = []
vendor_sources = []

try:
    subprocess.check_call(["pkg-config", "--exists", "liburing"], stderr=subprocess.DEVNULL)
    define_macros.append(("FREASTAL_IOURING", "1"))
    include_dirs += [f[2:] for f in pkg_config("--cflags-only-I", "liburing") if f.startswith("-I")]
    library_dirs += [f[2:] for f in pkg_config("--libs-only-L",   "liburing") if f.startswith("-L")]
    libraries    += ["uring"]
    print("freastal: liburing found – io_uring path ENABLED")
except (subprocess.CalledProcessError, FileNotFoundError):
    pass

# ---------- OpenSSL + vendored picotls (optional, enables TLS 1.3) ----------

src_dir     = os.path.join("freastal", "src")
vendor_php  = os.path.join("vendor", "picohttpparser")
vendor_ptls = os.path.join("vendor", "picotls")

ssl_includes = pkg_config("--cflags-only-I", "openssl")
ssl_ldflags  = pkg_config("--libs-only-L",   "openssl")
ssl_inc = [f[2:] for f in ssl_includes if f.startswith("-I")]
ssl_lib = [f[2:] for f in ssl_ldflags  if f.startswith("-L")]

# Verify we can actually find OpenSSL headers before enabling TLS
has_openssl = bool(ssl_inc) or any(
    os.path.exists(os.path.join(d, "openssl", "ssl.h"))
    for d in ["/usr/include", "/usr/local/include", "/opt/homebrew/include"]
)

if has_openssl:
    define_macros.append(("FREASTAL_TLS", "1"))
    include_dirs += ssl_inc
    library_dirs += ssl_lib
    libraries    += ["ssl", "crypto"]
    vendor_sources = [
        os.path.join(vendor_ptls, "lib", "picotls.c"),
        os.path.join(vendor_ptls, "lib", "openssl.c"),
        os.path.join(vendor_ptls, "lib", "pembase64.c"),
        os.path.join(vendor_ptls, "lib", "hpke.c"),
        os.path.join(vendor_ptls, "lib", "asn1.c"),
    ]
    print("freastal: OpenSSL found – TLS 1.3 ENABLED (vendored picotls)")
else:
    print("freastal: OpenSSL not found – TLS 1.3 DISABLED")

ext = Extension(
    "freastal._freastal",
    sources=[
        # vendored third-party
        os.path.join(vendor_php, "picohttpparser.c"),
        *vendor_sources,
        # freastal
        os.path.join(src_dir, "server.c"),
        os.path.join(src_dir, "wsgi.c"),
        os.path.join(src_dir, "asgi.c"),
        os.path.join(src_dir, "tls.c"),
        os.path.join(src_dir, "freastalmodule.c"),
    ],
    include_dirs=[
        src_dir,
        vendor_php,
        os.path.join(vendor_ptls, "include"),
        os.path.join(vendor_ptls, "lib"),   # internal headers (wincompat.h, chacha20poly1305.h)
    ] + include_dirs,
    library_dirs=library_dirs,
    libraries=libraries,
    define_macros=define_macros,
    extra_compile_args=[
        "-O3",
        "-march=native",
        "-fvisibility=hidden",
        "-Wall",
        "-Wextra",
        "-Wno-unused-parameter",
    ],
)

setup(ext_modules=[ext])
