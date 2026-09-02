"""environ construction: PEP 3333 semantics, mutability, and key-table presizing.

build_environ() clones a pre-built template dict instead of growing a fresh
dict per request.  These tests pin down both halves of that: the environ the
application sees must be an ordinary, fully mutable dict with exactly the
documented contents, and it must arrive with enough spare key-table capacity
that inserting the request headers never triggers a dictresize.
"""

import http.client
import multiprocessing
import socket
import sys
import time

import pytest

import freastal

REQUIRED = {
    "REQUEST_METHOD": str,
    "SCRIPT_NAME": str,
    "PATH_INFO": str,
    "QUERY_STRING": str,
    "SERVER_NAME": str,
    "SERVER_PORT": str,
    "SERVER_PROTOCOL": str,
    "REMOTE_ADDR": str,
    "wsgi.version": tuple,
    "wsgi.url_scheme": str,
    "wsgi.multithread": bool,
    "wsgi.multiprocess": bool,
    "wsgi.run_once": bool,
}


def _environ_app(environ, start_response):
    """Report on the environ dict, then prove it is fully mutable."""
    report = {
        "keys": list(environ),
        "len": len(environ),
        "none_values": [k for k, v in environ.items() if v is None],
        "types": {k: type(environ[k]).__name__ for k in REQUIRED if k in environ},
        "has_input": hasattr(environ.get("wsgi.input"), "read"),
        "has_errors": hasattr(environ.get("wsgi.errors"), "write"),
        # How many extra keys fit before CPython has to grow the key table.
        # A dict grown from empty would have <= 3 spare slots at this size.
        "spare": _spare_capacity(environ),
    }

    # The application is allowed to do all of this to environ.
    probe = environ.copy()
    assert len(probe) == report["len"]
    assert "PATH_INFO" in probe and probe.get("PATH_INFO") == environ["PATH_INFO"]
    del environ["SCRIPT_NAME"]
    environ["SCRIPT_NAME"] = "/mounted"
    environ["custom.key"] = object()
    environ[42] = "non-string key"
    del environ[42]
    report["after_mutation"] = (len(environ), environ["SCRIPT_NAME"])

    body = repr(report).encode()
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [body]


def _spare_capacity(d):
    """Number of inserts d absorbs before its key table is reallocated."""
    probe = d.copy()  # never mutate the real environ
    base = sys.getsizeof(probe)
    n = 0
    for i in range(4096):
        probe[f"__spare_probe_{i}__"] = None
        if sys.getsizeof(probe) != base:
            break
        n += 1
    return n


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(port):
    freastal.serve(_environ_app, host="127.0.0.1", port=port, reuse_port=False)


@pytest.fixture(scope="module")
def environ_server():
    port = _free_port()
    p = multiprocessing.Process(target=_run, args=(port,), daemon=True)
    p.start()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        p.terminate()
        raise RuntimeError("server did not start")
    yield port
    p.terminate()
    p.join(timeout=3)


def _fetch(port, path="/", headers=None, method="GET", body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        assert resp.status == 200
        return eval(resp.read().decode())
    finally:
        conn.close()


def test_environ_is_pep3333_compliant(environ_server):
    r = _fetch(environ_server, "/some/path?x=1")
    for key, typ in REQUIRED.items():
        assert key in r["keys"], f"missing {key}"
        assert r["types"][key] == typ.__name__, key
    assert r["has_input"] and r["has_errors"]


def test_no_placeholder_values_leak(environ_server):
    """The template seeds per-request slots with None; none may survive."""
    for path, headers, method, body in [
        ("/", None, "GET", None),
        ("/q?a=1", None, "GET", None),
        ("/p", {"Content-Type": "text/plain"}, "POST", b"xyz"),
        ("/", {"X-A": "1", "X-B": "2"}, "GET", None),
    ]:
        r = _fetch(environ_server, path, headers, method, body)
        assert r["none_values"] == [], (path, r["none_values"])


def test_environ_is_mutable(environ_server):
    r = _fetch(environ_server, "/")
    n, script_name = r["after_mutation"]
    assert script_name == "/mounted"
    assert n == r["len"] + 1  # custom.key added, SCRIPT_NAME re-added


def test_key_order_matches_construction_order(environ_server):
    r = _fetch(environ_server, "/x?y=1", {"X-One": "1", "X-Two": "2"})
    keys = r["keys"]
    core = [
        "wsgi.version",
        "wsgi.url_scheme",
        "wsgi.multithread",
        "wsgi.multiprocess",
        "wsgi.run_once",
        "SERVER_NAME",
        "SERVER_PORT",
        "SERVER_SOFTWARE",
        "SCRIPT_NAME",
        "wsgi.errors",
        "REQUEST_METHOD",
        "PATH_INFO",
        "QUERY_STRING",
        "SERVER_PROTOCOL",
        "REMOTE_ADDR",
        "wsgi.input",
    ]
    assert keys[: len(core)] == core
    # request headers follow, in wire order
    assert keys.index("HTTP_X_ONE") < keys.index("HTTP_X_TWO")


def test_many_headers_still_correct(environ_server):
    """More headers than the template's spare capacity: dict resizes normally."""
    headers = {f"X-Q{i}": f"v{i}" for i in range(45)}
    r = _fetch(environ_server, "/lots", headers)
    for i in range(45):
        assert f"HTTP_X_Q{i}" in r["keys"]
    assert r["none_values"] == []


def test_environ_key_table_is_presized(environ_server):
    """Regression guard: environ must arrive over-allocated, not grown from empty.

    A dict grown one insert at a time to ~18 entries lands in a 32-slot key
    table with only ~3 spare slots (and got there via three key-table
    allocations and two rebuilds).  build_environ() clones a template whose
    table was pre-grown to 64 slots, so a typical request has ~20 spare slots
    and never resizes.  If this fails on a new CPython, environ is still
    correct -- the template just stopped buying head-room and build_environ()
    is back to paying for dictresize.
    """
    r = _fetch(environ_server, "/", {"X-A": "1", "X-B": "2"})
    grown_from_empty = {}
    for i in range(r["len"]):
        grown_from_empty[f"k{i:03d}"] = i
    base = sys.getsizeof(grown_from_empty)
    naive_spare = 0
    for i in range(4096):
        grown_from_empty[f"__p{i}__"] = None
        if sys.getsizeof(grown_from_empty) != base:
            break
        naive_spare += 1

    assert r["spare"] > naive_spare, (
        f"environ has {r['spare']} spare key slots for {r['len']} entries; "
        f"a dict grown from empty would have {naive_spare} -- presizing is not "
        "taking effect"
    )
    assert r["spare"] >= 10, r["spare"]
