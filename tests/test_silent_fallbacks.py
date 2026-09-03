"""Capabilities and inputs that used to be accepted and then quietly ignored.

Both bugs here shared a shape: something the caller asked for could not be
honoured, and the server carried on without it rather than saying so.  Neither
had a symptom -- the server came up, served requests, and returned 200s -- so
the only thing that could catch either is a test that looks at *what* it came
up as.

  * A certfile on a build without OpenSSL was accepted and dropped, and the
    server listened in plaintext on the port the caller meant to be TLS.
  * host="localhost" failed to parse as IPv4 and bound 0.0.0.0 on the
    requested port, so a caller asking for loopback got every interface.
"""

import os
import socket
import subprocess
import sys
import textwrap
import time

import pytest

import freastal


@pytest.fixture
def free_port():
    """A port that was free a moment ago.

    Same approach as conftest's helper: bind 0, read the port back, release
    it.  Racy in principle; in practice the window is short and the
    alternative is a fixed port that collides with a parallel run.
    """
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------
# The bind address actually used.
#
# Driven out of process: the failure is which interface the listener ends up
# on, and the only way to see that is to ask the OS about a real listening
# socket.  A raised exception is checked in-process below.
# --------------------------------------------------------------------------

_SERVER_SRC = textwrap.dedent(
    """
    import sys, freastal
    def app(environ, start_response):
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"hi"]
    try:
        freastal.serve(app, host=sys.argv[1], port=int(sys.argv[2]),
                       reuse_port=False)
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(7)
    """
)


def _serve_and_report(host, port, timeout=6):
    """Start a server on `host` in a child; return (exit_code, stderr).

    Exit code 7 means serve() raised, which is the fixed behaviour for a host
    freastal cannot parse.  A child still running when the timeout expires
    means it bound something, and the caller inspects what.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", _SERVER_SRC, host, str(port)],
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _out, err = proc.communicate(timeout=timeout)
        return proc.returncode, err
    except subprocess.TimeoutExpired:
        proc.kill()
        _out, err = proc.communicate()
        return None, err


def _connect(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


@pytest.mark.parametrize("host", ["localhost", "example.com", "not a host", ""])
def test_a_host_that_is_not_an_ipv4_literal_is_refused(host, free_port):
    """serve() raises instead of binding something the caller did not ask for.

    "localhost" is the one that matters: it is the obvious thing to write for
    "loopback only", it is not a dotted quad, and it used to bind every
    interface.  The others are here because the same parse failure covers them
    and none should reach a listening socket.
    """
    code, err = _serve_and_report(host, free_port)
    assert code == 7, f"expected serve() to raise for host={host!r}, got {code}: {err}"
    assert "dotted-quad" in err, err
    # The message has to say what to write instead, or it just moves the
    # confusion; "localhost" reads as valid to anyone who has used any other
    # server.
    assert "127.0.0.1" in err, err


def test_a_dotted_quad_still_binds_only_that_interface(free_port):
    """The control: the fix must not have broken the address that worked."""
    proc = subprocess.Popen(
        [sys.executable, "-c", _SERVER_SRC, "127.0.0.1", str(free_port)],
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not _connect("127.0.0.1", free_port):
            if proc.poll() is not None:
                _out, err = proc.communicate()
                pytest.fail(f"server exited early: {err}")
            time.sleep(0.1)
        assert _connect("127.0.0.1", free_port), "server never came up on 127.0.0.1"
    finally:
        proc.kill()
        proc.communicate()


# --------------------------------------------------------------------------
# TLS asked for on a build that cannot provide it.
#
# This needs a genuinely TLS-less build, which no machine that can build TLS
# will produce by accident -- FREASTAL_NO_TLS=1 exists so the guard is
# reachable.  Building one takes a compile, so it is a single test that does
# the whole story rather than several that each pay for it.
# --------------------------------------------------------------------------


def test_has_tls_reports_this_build():
    """The capability is visible at all, which is the premise of the guard.

    Deliberately not asserting a particular value: this same test runs on the
    no-OpenSSL CI build, where False is the correct answer.  What matters is
    that the answer exists and agrees with what the server will actually do,
    which the tests either side of this one check.
    """
    assert isinstance(freastal.has_tls, bool)


def test_tls_tests_are_not_silently_skipped():
    """A TLS build must actually have run the TLS suite.

    Without this, losing TLS from a build would turn every test in
    test_tls.py into a skip and the suite would still be green -- the same
    silent-downgrade shape as the bug this file is about, one level up.
    """
    if os.environ.get("FREASTAL_NO_TLS") == "1":
        pytest.skip("build deliberately has no TLS")
    assert freastal.has_tls, (
        "this build has no TLS, so the TLS suite is skipping; if that is "
        "intended, set FREASTAL_NO_TLS=1 so it is a stated choice"
    )


def test_a_certfile_on_a_tls_less_build_raises_instead_of_serving_plaintext(
    tmp_path, free_port
):
    """The bug: cert accepted, TLS dropped, body served in the clear.

    Asserted end to end against a real TLS-less build rather than by mocking
    the flag, because the thing under test is what the C layer does when
    FREASTAL_TLS is undefined -- exactly the configuration a wheel built
    without OpenSSL headers ships.
    """
    if not os.environ.get("FREASTAL_SLOW_TESTS"):
        pytest.skip("needs a from-source rebuild; set FREASTAL_SLOW_TESTS=1")

    root = os.path.dirname(os.path.dirname(os.path.abspath(freastal.__file__)))
    build = tmp_path / "notls"
    env = dict(os.environ, FREASTAL_NO_TLS="1")

    r = subprocess.run(
        # Build isolation on purpose: it pulls in setuptools/wheel, which the
        # test venv need not have, and FREASTAL_NO_TLS still reaches the build.
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--target",
            str(build),
            "--no-deps",
            "-q",
            root,
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr[-2000:]

    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )

    probe = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {str(build)!r})
        import freastal
        assert freastal.has_tls is False, "forced build still has TLS"
        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"SECRET"]
        try:
            freastal.serve(app, host="127.0.0.1", port={free_port},
                           reuse_port=False,
                           certfile={str(cert)!r}, keyfile={str(key)!r})
        except RuntimeError as exc:
            print(f"REFUSED: {{exc}}")
            sys.exit(0)
        sys.exit(9)   # came up -- it is serving something, in the clear
        """
    )
    r = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert r.returncode == 0, (
        "a TLS-less build accepted certfile/keyfile instead of refusing them; "
        f"rc={r.returncode} out={r.stdout!r} err={r.stderr[-800:]!r}"
    )
    assert "REFUSED" in r.stdout, r.stdout
    assert "plaintext" in r.stdout, "the error should say what the risk is"
