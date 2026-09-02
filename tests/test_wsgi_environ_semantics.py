"""The WSGI environ: what it contains, and what a request can put in it.

environ is built by copying a server-wide template, so these tests pin down
the two things that can go wrong with that: a templated default leaking a
value from an earlier request, and a key that only some requests should have
being present on all of them.  The rest cover request-header decoding, which
has to be latin-1 (PEP 3333) and has to join repeated field lines (RFC 9110
5.3) rather than keeping only the last one.
"""

import json
import socket
import subprocess
import sys
import time

import pytest


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


APP = r"""
import json, sys
import freastal

def app(environ, start_response):
    p = environ["PATH_INFO"]

    if p == "/dump":
        payload = {
            "keys": sorted(environ),
            "is_dict": type(environ) is dict,
            "strs": {k: v for k, v in environ.items() if isinstance(v, str)},
            "version": list(environ["wsgi.version"]),
            "multithread": environ["wsgi.multithread"],
            "multiprocess": environ["wsgi.multiprocess"],
            "run_once": environ["wsgi.run_once"],
            "errors_is_stderr": environ["wsgi.errors"] is sys.stderr,
            "input_read": environ["wsgi.input"].read().decode("latin-1"),
        }
        # Vandalise it the way middleware does.  The next request on this
        # connection must not see any of it.
        environ["PATH_INFO"] = "/rewritten"
        environ["SCRIPT_NAME"] = "/mounted"
        environ["QUERY_STRING"] = "leaked=1"
        environ["SERVER_PROTOCOL"] = "HTTP/0.9"
        environ["wsgi.input"] = None
        environ["wsgi.url_scheme"] = "gopher"
        environ["freastal.injected"] = "yes"
        body = json.dumps(payload).encode()
    elif p == "/headers":
        body = "\n".join(
            "%s=%s" % (k, v) for k, v in sorted(environ.items())
            if k.startswith("HTTP_")
        ).encode("latin-1")
    else:
        body = b"ok"

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [body]

freastal.serve(app, host="127.0.0.1", port=PORT, workers=1, reuse_port=False)
"""


def _spawn(port):
    proc = subprocess.Popen(
        [sys.executable, "-c", f"PORT = {port}\n" + APP],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25) as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                if s.recv(64):
                    return proc
        except OSError:
            time.sleep(0.05)
    proc.kill()
    raise RuntimeError("server did not start")


@pytest.fixture(scope="module")
def port():
    p = free_port()
    proc = _spawn(p)
    yield p
    proc.kill()
    proc.wait(timeout=10)


def _bodies(port, requests):
    """Send raw requests down one connection and return one body per response."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(b"".join(requests))
        buf = b""
        bodies = []
        while len(bodies) < len(requests):
            head, sep, rest = buf.partition(b"\r\n\r\n")
            if sep:
                length = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":")[1])
                if len(rest) >= length:
                    bodies.append(rest[:length])
                    buf = rest[length:]
                    continue
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    assert len(bodies) == len(requests), bodies
    return bodies


def _get(port, target, headers=(b"Host: x",), version=b"HTTP/1.1"):
    req = b"GET " + target + b" " + version + b"\r\n"
    for h in headers:
        req += h + b"\r\n"
    return req + b"\r\n"


# --- template: no leakage, no phantom keys -------------------------------


def test_environ_is_a_fresh_plain_dict_untouched_by_the_previous_request(port):
    """Two identical requests on one connection must see identical environs."""
    req = _get(port, b"/dump")
    first, second = (json.loads(b) for b in _bodies(port, [req, req]))

    assert first["is_dict"] is True
    assert first == second, "environ carried state across requests"
    assert "freastal.injected" not in second["keys"]
    assert second["strs"]["PATH_INFO"] == "/dump"
    assert second["strs"]["SCRIPT_NAME"] == ""
    assert second["strs"]["QUERY_STRING"] == ""
    assert second["strs"]["SERVER_PROTOCOL"] == "HTTP/1.1"
    assert second["strs"]["wsgi.url_scheme"] == "http"
    assert second["input_read"] == ""


def test_required_pep3333_keys_are_present(port):
    env = json.loads(_bodies(port, [_get(port, b"/dump")])[0])
    for key in (
        "REQUEST_METHOD",
        "SCRIPT_NAME",
        "PATH_INFO",
        "QUERY_STRING",
        "SERVER_NAME",
        "SERVER_PORT",
        "SERVER_PROTOCOL",
        "SERVER_SOFTWARE",
        "REMOTE_ADDR",
        "wsgi.version",
        "wsgi.url_scheme",
        "wsgi.input",
        "wsgi.errors",
        "wsgi.multithread",
        "wsgi.multiprocess",
        "wsgi.run_once",
    ):
        assert key in env["keys"], key
    assert env["version"] == [1, 0]
    assert env["multithread"] is False
    assert env["multiprocess"] is True
    assert env["run_once"] is False
    assert env["errors_is_stderr"] is True
    assert env["strs"]["REQUEST_METHOD"] == "GET"
    assert env["strs"]["REMOTE_ADDR"] == "127.0.0.1"


def test_bodyless_request_has_no_content_keys(port):
    """CONTENT_TYPE/CONTENT_LENGTH are only there when the request sent them,
    so neither may be templated in with a placeholder."""
    env = json.loads(_bodies(port, [_get(port, b"/dump")])[0])
    assert "CONTENT_TYPE" not in env["keys"]
    assert "CONTENT_LENGTH" not in env["keys"]


def test_content_keys_appear_when_the_request_carries_a_body(port):
    req = (
        b"POST /dump HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n"
        b"Content-Length: 5\r\n\r\nhello"
    )
    env = json.loads(_bodies(port, [req])[0])
    assert env["strs"]["CONTENT_TYPE"] == "text/plain"
    assert env["strs"]["CONTENT_LENGTH"] == "5"
    assert env["strs"]["REQUEST_METHOD"] == "POST"
    assert env["input_read"] == "hello"


def test_query_string_and_http_10_override_their_template_defaults(port):
    q = json.loads(_bodies(port, [_get(port, b"/dump?a=1&b=2")])[0])
    assert q["strs"]["QUERY_STRING"] == "a=1&b=2"
    assert q["strs"]["PATH_INFO"] == "/dump"

    # HTTP/1.0 without keep-alive, so this needs its own connection.
    old = json.loads(_bodies(port, [_get(port, b"/dump", version=b"HTTP/1.0")])[0])
    assert old["strs"]["SERVER_PROTOCOL"] == "HTTP/1.0"

    # ...and the 1.0 request must not have left HTTP/1.0 behind.
    again = json.loads(_bodies(port, [_get(port, b"/dump")])[0])
    assert again["strs"]["SERVER_PROTOCOL"] == "HTTP/1.1"


# --- request header decoding ---------------------------------------------


def _pairs(port, headers):
    body = _bodies(port, [_get(port, b"/headers", headers=headers)])[0]
    return dict(
        line.split("=", 1) for line in body.decode("latin-1").split("\n") if line
    )


def test_obs_text_header_value_is_decoded_as_latin1(port):
    """A single 0xff byte used to make the UTF-8 decode fail, which returned a
    500 with the exception still set when the app was called."""
    seen = _pairs(port, [b"Host: x", b"X-Latin: caf\xe9\xff"])
    assert seen["HTTP_X_LATIN"] == "caf\xe9\xff"


def test_obs_text_in_the_request_target_is_decoded_as_latin1(port):
    body = _bodies(port, [_get(port, b"/dump?q=caf\xe9")])[0]
    assert json.loads(body)["strs"]["QUERY_STRING"] == "q=caf\xe9"


def test_repeated_header_lines_are_joined(port):
    """RFC 9110 5.3: repeated field lines mean one value joined by ", ".
    They used to silently overwrite, so only the last one survived."""
    seen = _pairs(port, [b"Host: x", b"X-Dup: a", b"X-Dup: b", b"X-Dup: c"])
    assert seen["HTTP_X_DUP"] == "a, b, c"


def test_repeated_cookie_lines_are_joined_with_a_semicolon(port):
    """RFC 6265 5.4 spells Cookie's list form with "; "."""
    seen = _pairs(port, [b"Host: x", b"Cookie: a=1", b"Cookie: b=2"])
    assert seen["HTTP_COOKIE"] == "a=1; b=2"


def test_repeated_header_with_an_identical_one_byte_value_still_joins(port):
    """A one-byte latin-1 decode returns an interned singleton, so presence
    cannot be decided by comparing the stored value to the new one."""
    seen = _pairs(port, [b"Host: x", b"X-One: 1", b"X-One: 1"])
    assert seen["HTTP_X_ONE"] == "1, 1"


def test_an_uncached_header_name_repeated_also_joins(port):
    """The joining path has to work for a key built on the fly as well as for
    one taken out of the header-name cache."""
    seen = _pairs(port, [b"Host: x", b"X-Odd-Thing: p", b"X-Odd-Thing: q"])
    assert seen["HTTP_X_ODD_THING"] == "p, q"
