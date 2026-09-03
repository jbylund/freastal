"""The session-ticket key ring shared across workers.

test_tls.py covers the ring inside one process.  This file covers the part
that only exists once there is more than one: with a ring per worker, a ticket
sealed by worker A cannot be opened by worker B, so a reconnect resumes only
when the kernel happens to hand it back to the issuing worker -- 1/N, and
completely invisible, because picotls turns an undecryptable ticket into the
full handshake a first-time client would have had anyway.

Two things here are worth more than the hit rate, and both are about the key
material rather than about resumption:

  * Rotation has to be lockstep.  Rings that each roll on their own timer
    agree at startup and disagree an hour later, which is a failure that would
    pass every test that does not rotate -- so the rotation tests here drive
    real rotations and then check that *every* worker still agrees.
  * A retired key has to be destroyed, in shared memory, for all of the
    processes mapping it at once.  That is the entire justification for the
    parent owning rotation rather than every worker deriving epochs from one
    shared seed, and it is asserted against the bytes of the region rather
    than inferred from behaviour.
"""

import http.client
import mmap
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

# tests/ is on sys.path -- pytest's rootdir insertion, not a package -- so the
# certificate factory is shared rather than reimplemented.  A function rather
# than the fixture itself: pytest registers a fixture under the name it is
# bound to in this module, and a `certpair` bound here would shadow every
# test's own parameter of that name.
from test_tls import OPENSSL, free_port, mint_certpair, tls_context

import freastal
from freastal import _freastal

pytestmark = pytest.mark.skipif(
    not freastal.has_tls, reason="this build has no TLS support"
)


@pytest.fixture(scope="module")
def certpair(tmp_path_factory):
    if OPENSSL is None:
        pytest.skip("openssl not available to mint a test certificate")
    return mint_certpair(str(tmp_path_factory.mktemp("certs")))


BODY = b"tls-body"
WORKERS = 4
# Enough concurrent reconnects to land on several workers, few enough that the
# handshakes do not dominate the run time.
RECONNECTS = 24
CLOSE_REQUEST = b"GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


# ---------------------------------------------------------------------------
# A multi-worker TLS server.
#
# Written to a real file rather than passed to `python -c`, because spawn and
# forkserver re-import the main module by path and there is no path for -c.
# ---------------------------------------------------------------------------

APP_SRC = textwrap.dedent(
    '''
    """Multi-worker TLS app for tests/test_tls_ticket_ring.py."""
    import os
    import sys

    import freastal
    from freastal._freastal import _rotate_ticket_key

    BODY = b"tls-body"


    def app(environ, start_response):
        path = environ["PATH_INFO"]
        if path == "/rotate":
            # Runs in a WORKER, which does not own the ring and cannot write
            # it.  The hook asks the owner and waits for the new key to become
            # visible through the shared mapping before returning, so a 200
            # here means the rotation is published, not merely requested.
            _rotate_ticket_key()
            body = b"rotated"
        elif path == "/pid":
            body = str(os.getpid()).encode()
        else:
            body = BODY
        start_response(
            "200 OK",
            [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))],
        )
        return [body]


    if __name__ == "__main__":
        port, cert, key, workers, method = (
            int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
        )
        if method != "default":
            import multiprocessing

            multiprocessing.set_start_method(method, force=True)
        freastal.serve(
            app,
            host="127.0.0.1",
            port=port,
            workers=workers,
            reuse_port=None,
            certfile=cert,
            keyfile=key,
        )
    '''
).lstrip()


def request_over_new_connection(port, ctx, session=None, path=b"/"):
    """One request on a connection of its own, read to EOF.

    Reading to EOF is what makes the ticket observable: a NewSessionTicket
    arrives after the response, so a client that stops at the end of the body
    may never see it.
    """
    raw = socket.create_connection(("127.0.0.1", port), timeout=20)
    with ctx.wrap_socket(raw, server_hostname="localhost", session=session) as sock:
        sock.sendall(CLOSE_REQUEST % path)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return sock.session, sock.session_reused, b"".join(chunks)


def resume_many(port, ctx, session, n=RECONNECTS):
    """n concurrent reconnects offering `session`. Returns how many resumed.

    Concurrent rather than sequential on purpose: the point is to be spread
    across workers by the kernel, and a serial client can be handed the same
    worker every time.
    """
    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(
            pool.map(
                lambda _: request_over_new_connection(port, ctx, session)[1], range(n)
            )
        )
    return sum(1 for r in results if r)


def worker_pids(port, ctx, n=RECONNECTS):
    with ThreadPoolExecutor(max_workers=n) as pool:
        bodies = list(
            pool.map(
                lambda _: request_over_new_connection(port, ctx, path=b"/pid")[2],
                range(n),
            )
        )
    return {b.rsplit(b"\r\n\r\n", 1)[-1] for b in bodies}


def rotate(port, ctx):
    """Advance the ring, over a connection of its own.

    A fresh connection so this never rides on the session under measurement,
    and over HTTP because the hook has to run in a server process: rotating in
    the test process would rotate a ring no server has.
    """
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=30)
    try:
        conn.request("GET", "/rotate")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200, (resp.status, body)
        assert body == b"rotated", body
    finally:
        conn.close()


def start_server(certpair, workers, method, tmp_path):
    cert, key = certpair
    src = tmp_path / "ring_app.py"
    src.write_text(APP_SRC)
    port = free_port()
    errf = tempfile.NamedTemporaryFile("w+", delete=False)  # noqa: SIM115
    proc = subprocess.Popen(
        [sys.executable, str(src), str(port), cert, key, str(workers), method],
        stdout=errf,  # the workers announce themselves on stdout
        stderr=errf,
    )

    def output():
        errf.flush()
        with open(errf.name) as f:
            return f.read()

    # Answering is not enough: one worker answers exactly like four, and a
    # test that measured resumption against a server that had quietly come up
    # with one would pass no matter what the ring did.  Wait until every
    # worker has said it is running.
    # workers=1 serves in this process and announces no workers at all, which
    # is itself the thing test_workers_one_creates_no_shared_ring checks.
    started = re.compile(r"worker \d+ pid=(\d+) starting")
    want = workers if workers > 1 else 0
    deadline = time.time() + 60
    while time.time() < deadline:
        if proc.poll() is not None:
            pytest.fail(f"the {workers}-worker server exited:\n{output()[-2000:]}")
        text = output()
        if len(set(started.findall(text))) >= want:
            try:
                request_over_new_connection(port, tls_context())
                return proc, port, output
            except (OSError, ssl.SSLError):
                pass
        time.sleep(0.1)
    proc.kill()
    pytest.fail(
        f"only {len(set(started.findall(output())))} of {want} workers "
        f"started, or the server never answered:\n{output()[-2000:]}"
    )


def start_methods():
    """The start methods to run the worker tests under, on this platform.

    Forcing the non-default ones on Linux is the point: fork inherits the
    descriptor and never pickles the Process arguments at all, so it does not
    exercise the handover, and forkserver -- Linux's default from 3.14 -- goes
    through a third process that neither of the others does.

    Only "default" elsewhere.  macOS offers fork and forkserver and both are
    documented as unsafe there (a forked CPython on macOS can deadlock or
    crash inside system frameworks), so running them would be testing
    multiprocessing rather than freastal.
    """
    import multiprocessing

    if not sys.platform.startswith("linux"):
        return ["default"]
    available = set(multiprocessing.get_all_start_methods())
    return ["default"] + sorted(available & {"spawn", "fork", "forkserver"})


@pytest.fixture(scope="module", params=start_methods())
def ring_server(request, certpair, tmp_path_factory):
    proc, port, output = start_server(
        certpair, WORKERS, request.param, tmp_path_factory.mktemp("ring")
    )
    # A worker announces itself before it gets as far as TLS setup, so having
    # answered is not yet proof that all four joined the shared ring.  Wait
    # for the banners rather than sampling once: the difference between four
    # workers on one ring and four workers on four rings is the entire subject
    # of this file, and it must not be something the tests infer.
    deadline = time.time() + 30
    while time.time() < deadline:
        text = output()
        if text.count("ring shared with the other workers") >= WORKERS:
            break
        time.sleep(0.1)
    text = output()
    assert "key ring shared with the workers" in text, (
        f"no shared ring was created, so these tests would be measuring "
        f"{WORKERS} independent rings:\n{text[-2000:]}"
    )
    assert text.count("ring shared with the other workers") >= WORKERS, (
        f"only {text.count('ring shared with the other workers')} of {WORKERS} "
        f"workers joined the shared ring:\n{text[-2000:]}"
    )
    yield port, output
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


# ---------------------------------------------------------------------------
# Resumption across workers.
# ---------------------------------------------------------------------------


def test_a_ticket_resumes_on_every_worker(ring_server):
    """The whole point: a ticket issued by one worker opens on all of them.

    The `pids` assertion is not decoration.  Without it a server that ran one
    worker, or a kernel that handed every connection to the same one, would
    pass this test at 100% while proving nothing about sharing at all -- which
    is exactly the shape of the bug being fixed.
    """
    port, _output = ring_server
    ctx = tls_context()

    session, reused, body = request_over_new_connection(port, ctx)
    assert not reused, "the first connection resumed, with nothing to resume from"
    assert body.endswith(BODY), body[-200:]
    assert session is not None and session.ticket_lifetime_hint > 0, (
        "no NewSessionTicket was issued, so there is nothing to share"
    )

    pids = worker_pids(port, ctx)
    assert len(pids) > 1, (
        f"only {pids} served {RECONNECTS} concurrent connections, so this run "
        f"cannot tell a shared ring from a per-worker one"
    )

    hits = resume_many(port, ctx, session)
    assert hits == RECONNECTS, (
        f"{hits}/{RECONNECTS} reconnects resumed across {len(pids)} workers. "
        f"A per-worker ring scores about 1/N here; anything short of all of "
        f"them means some worker is sealing or unsealing under a key of its own"
    )


def test_workers_agree_after_a_rotation(ring_server):
    """Lockstep, which is the failure that would otherwise appear an hour in.

    Rotation is requested through *a* worker, which cannot write the ring
    itself; it asks the owner and waits.  What is asserted is that the answer
    reaches every other worker too, so the ring stays one ring rather than
    drifting into N.
    """
    port, _output = ring_server
    ctx = tls_context()

    rotate(port, ctx)

    session, reused, _body = request_over_new_connection(port, ctx)
    assert not reused
    assert session is not None and session.ticket_lifetime_hint > 0

    hits = resume_many(port, ctx, session)
    assert hits == RECONNECTS, (
        f"after one rotation only {hits}/{RECONNECTS} reconnects resumed: the "
        f"workers no longer agree on the sealing key, which is what N "
        f"independent rotation timers on one ring would look like"
    )


def test_a_ticket_survives_rotation_until_its_key_leaves_the_ring(ring_server):
    """The ring's contract, checked across processes rather than within one.

    A ticket keeps resuming across RING-1 rotations because that is how many
    happen before its slot is reused, and the RING'th destroys the key.  On
    every worker: a key that survived in one worker and not another would be
    the divergence this feature exists to remove, and would show up here as a
    partial score rather than a clean all-or-nothing.
    """
    port, _output = ring_server
    ring = _freastal.TICKET_RING_SLOTS
    ctx = tls_context()

    session, reused, _body = request_over_new_connection(port, ctx)
    assert not reused
    assert session is not None and session.ticket_lifetime_hint > 0

    for step in range(ring - 1):
        rotate(port, ctx)
        hits = resume_many(port, ctx, session)
        assert hits == RECONNECTS, (
            f"{hits}/{RECONNECTS} resumed after {step + 1} rotation(s); the "
            f"ring holds {ring} keys, so every worker should still have this one"
        )

    for _ in range(ring):
        rotate(port, ctx)
    hits = resume_many(port, ctx, session)
    assert hits == 0, (
        f"{hits}/{RECONNECTS} reconnects still resumed after {ring} further "
        f"rotations. The key was destroyed in the shared ring, so a worker "
        f"that still opens this ticket is holding a private copy of a retired "
        f"key -- which is the property rotation exists to provide"
    )
    _s, _reused, body = request_over_new_connection(port, ctx, session=session)
    assert body.endswith(BODY), "falling back must still serve the request"


def test_workers_one_creates_no_shared_ring(certpair, tmp_path):
    """The common case must not pay for any of this.

    workers=1 keeps the process-local ring and its libuv timer; it never
    creates a shared region, never starts a rotation thread, and never touches
    SIGUSR1.  The banner is the observable that says which ring is in use.
    """
    proc, port, output = start_server(certpair, 1, "default", tmp_path)
    try:
        # One context for both: an SSLSession cannot be offered to a context
        # other than the one that produced it.
        ctx = tls_context()
        session, reused, body = request_over_new_connection(port, ctx)
        assert not reused
        assert body.endswith(BODY)
        assert session is not None and session.ticket_lifetime_hint > 0
        _s, resumed, _b = request_over_new_connection(port, ctx, session=session)
    finally:
        proc.terminate()
        proc.wait(timeout=15)

    err = output()
    assert resumed, "workers=1 stopped resuming"
    assert "ring private to this process" in err, err[-2000:]
    assert "shared with the workers" not in err, err[-2000:]


# ---------------------------------------------------------------------------
# The shared region itself.
#
# These map the ring directly and assert on its bytes.  Behaviour tests cannot
# tell "the key was destroyed" from "the key is still there and something
# declined to use it", and destruction is the claim the whole design rests on.
# ---------------------------------------------------------------------------

# The layout of tls_ticket_ring_t (server.h), for TLS_TICKET_RING_ABI 1.  The
# header carries enough to check that this copy is still right, and the test
# checks it rather than trusting it.
_RING_ABI = 1
_RING_MAGIC = 0x6672746B  # "frtk"
_RING_HDR = struct.Struct("=6I2i")  # magic abi slots stride rotate grace pid pad
_SEQ_OFF = 32
_CUR_OFF = 40
_DUE_OFF = 48
_KEYS_OFF = 56
_KEY_SIZE = 16 + 32 + 32 + 1  # name + aes + hmac + live


class attached_ring:
    """Create a ring and map it the way a worker does: read-only, MAP_SHARED.

    The mapping deliberately outlives _ticket_ring_destroy(), because "the
    owner's zeroize is visible in somebody else's mapping" is the thing under
    test.
    """

    def __enter__(self):
        self.fd = _freastal._ticket_ring_create()
        page = mmap.PAGESIZE
        self.len = ((_KEYS_OFF + 8 * _KEY_SIZE + page - 1) // page) * page
        self.map = mmap.mmap(
            self.fd, self.len, mmap.MAP_SHARED, mmap.PROT_READ, offset=0
        )
        return self

    def __exit__(self, *exc):
        self.map.close()
        os.close(self.fd)
        _freastal._ticket_ring_destroy()
        return False

    def header(self):
        magic, abi, slots, stride, rotate_ms, grace_ms, pid, _pad = _RING_HDR.unpack(
            self.map[: _RING_HDR.size]
        )
        return {
            "magic": magic,
            "abi": abi,
            "slots": slots,
            "stride": stride,
            "rotate_ms": rotate_ms,
            "grace_ms": grace_ms,
            "pid": pid,
        }

    def seq(self):
        return struct.unpack("=I", self.map[_SEQ_OFF : _SEQ_OFF + 4])[0]

    def cur(self):
        return struct.unpack("=i", self.map[_CUR_OFF : _CUR_OFF + 4])[0]

    def slot(self, i):
        off = _KEYS_OFF + i * _KEY_SIZE
        return self.map[off : off + _KEY_SIZE]

    def bytes(self):
        return self.map[: _KEYS_OFF + self.header()["slots"] * _KEY_SIZE]


def test_the_region_layout_is_the_one_these_tests_assume():
    """A guard on the tests below, which read raw offsets.

    If the struct changes without TLS_TICKET_RING_ABI changing, a worker built
    from the old header would read another one's keys out of the wrong
    offsets.  The header says what it is; this checks the answer.
    """
    with attached_ring() as ring:
        hdr = ring.header()
        assert hdr["magic"] == _RING_MAGIC, hex(hdr["magic"])
        assert hdr["abi"] == _RING_ABI, (
            f"the ring layout is at ABI {hdr['abi']}; the offsets in this file "
            f"are for ABI {_RING_ABI} and need updating with it"
        )
        assert hdr["stride"] == _KEY_SIZE, hdr
        assert hdr["slots"] == _freastal.TICKET_RING_SLOTS, hdr
        assert hdr["rotate_ms"] == _freastal.TICKET_ROTATE_MS, hdr
        assert hdr["pid"] == os.getpid(), hdr
        # Fully initialised before create() returns, so no worker can ever map
        # a half-written ring: one publish is two increments.
        assert ring.seq() == 2, ring.seq()
        assert ring.cur() == 0


def test_the_descriptor_handed_to_workers_cannot_be_mapped_writable():
    """A worker takes untrusted network input; it must not be able to write keys.

    A worker that could write here could plant a sealing key that every other
    worker then sealed under, turning one compromised worker into forged
    tickets for the whole server.  The descriptor is opened O_RDONLY for
    exactly this, so the refusal comes from the kernel rather than from a
    PROT_READ this file could have got wrong.
    """
    with attached_ring() as ring, pytest.raises(OSError):
        mmap.mmap(
            ring.fd,
            mmap.PAGESIZE,
            mmap.MAP_SHARED,
            mmap.PROT_READ | mmap.PROT_WRITE,
        )


def test_rotation_destroys_the_retired_key_in_every_mapping():
    """A retired key is gone from the shared page, not merely unreferenced.

    This is the difference between parent-owned rotation and the shared-seed
    design it was chosen over.  Under a seed, every epoch stays derivable
    forever and rotation bounds nothing; here the bytes are overwritten in the
    one physical page every worker has mapped, so they are gone from all of
    them at once.  Asserted against the region, because no amount of
    behavioural testing can distinguish a destroyed key from a retained one
    that nothing happens to be using.
    """
    with attached_ring() as ring:
        slots = ring.header()["slots"]
        original = bytes(ring.slot(0))
        # name + aes + hmac, minus the trailing `live` flag, which is 1 in
        # every filled slot and would match anywhere.
        secret = original[:-1]
        assert secret != bytes(len(secret)), "slot 0 was never minted"
        assert secret in bytes(ring.bytes())

        for step in range(slots - 1):
            _freastal._ticket_ring_rotate()
            assert secret in bytes(ring.bytes()), (
                f"the key was destroyed after {step + 1} rotation(s), but its "
                f"slot is not reused for {slots}: tickets it sealed would be "
                f"refused while still inside their advertised lifetime"
            )

        _freastal._ticket_ring_rotate()
        assert secret not in bytes(ring.bytes()), (
            "a retired ticket key is still readable in the shared region after "
            "its slot was reused"
        )
        # And what replaced it is a real key, not a hole: the ring must keep
        # sealing across a rotation.
        assert ring.cur() == 0
        assert bytes(ring.slot(0))[-1] == 1


def test_destroying_the_ring_zeroizes_it_through_another_mapping():
    """MAP_SHARED, stated as a test.

    MAP_PRIVATE would pass every resumption test at startup and then fail
    twice over: a worker would never see a rotation, and it would keep a
    private copy of every retired key for the life of the process.  Holding a
    second mapping across the destroy is what tells the two apart -- if this
    mapping still reads key material afterwards, the region was never shared.
    """
    ring = attached_ring().__enter__()
    try:
        before = bytes(ring.bytes())
        assert before[_KEYS_OFF:] != bytes(len(before) - _KEYS_OFF)
        _freastal._ticket_ring_destroy()
        after = bytes(ring.bytes())
        assert after == bytes(len(after)), (
            "the owner zeroized the ring and this process's mapping still has "
            "the keys, so the region is not actually shared"
        )
    finally:
        ring.map.close()
        os.close(ring.fd)
        _freastal._ticket_ring_destroy()


def test_a_second_ring_in_one_process_is_refused():
    """Two serve() calls in one process would leak the first ring's keys.

    The owner keeps one mapping, so a second create() would drop the first on
    the floor: unzeroized, still mapped by that server's workers, and with
    nothing left that could rotate it.  Refusing says so instead.
    """
    with attached_ring(), pytest.raises(RuntimeError, match="already owns"):
        _freastal._ticket_ring_create()


def test_the_region_has_no_name_in_the_filesystem():
    """Nothing to open by path, so nothing for another process to race.

    On Linux the region is a memfd and has no name anywhere at all.  Elsewhere
    it is a POSIX shm object created O_EXCL under 128 bits of CSPRNG and
    unlinked before create() returns, so by the time anything could look there
    is nothing to find.  /dev/shm is the only one of the two that is listable,
    which is why the assertion is Linux-only.
    """
    if not sys.platform.startswith("linux") or not os.path.isdir("/dev/shm"):
        pytest.skip("no listable POSIX shm namespace here")
    before = set(os.listdir("/dev/shm"))
    with attached_ring():
        during = set(os.listdir("/dev/shm"))
    assert during - before == set(), (
        f"the ticket ring left {during - before} in /dev/shm, where any "
        f"process on the box can see that it exists"
    )


def test_a_worker_refuses_a_ring_descriptor_that_is_not_one(certpair, tmp_path):
    """Refuse to start rather than fall back to a ring of this worker's own.

    A fallback would come up, serve every request correctly and resume about
    1/N of the time, which is indistinguishable from working -- the exact
    silent failure this change exists to remove.  So the failure is loud: the
    worker exits, and _run_workers turns that into a RuntimeError out of
    serve() rather than a server that looks fine.
    """
    cert, key = certpair
    junk = tmp_path / "not-a-ring"
    junk.write_bytes(b"\x00" * 65536)
    src = tmp_path / "bad_ring.py"
    src.write_text(
        textwrap.dedent(
            f"""
            import os
            from freastal import _freastal

            def app(environ, start_response):
                start_response("200 OK", [("Content-Length", "0")])
                return [b""]

            fd = os.open({str(junk)!r}, os.O_RDONLY)
            _freastal.serve(
                app, host="127.0.0.1", port={free_port()},
                certfile={cert!r}, keyfile={key!r}, ticket_ring_fd=fd,
            )
            """
        )
    )
    proc = subprocess.run(
        [sys.executable, str(src)], capture_output=True, timeout=90, check=False
    )
    assert proc.returncode != 0, (
        f"the server came up on a descriptor that is not a ticket ring, which "
        f"means it fell back to keys no other worker shares:\n"
        f"{proc.stdout[-500:]!r} {proc.stderr[-500:]!r}"
    )
    assert b"shared ticket ring" in proc.stderr, proc.stderr[-1000:]


# ---------------------------------------------------------------------------
# The constraint in server.h.
# ---------------------------------------------------------------------------


def _server_h():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "freastal", "src", "server.h")) as f:
        return f.read()


def test_the_ticket_lifetime_constraint_is_still_asserted():
    """Sharing the ring did not change what a client is promised.

    A ticket must not outlive the key that opens it, and ring arithmetic is
    ring arithmetic whoever is turning the ring: a worker that joins mid-epoch
    inherits a key whose destruction time was fixed when it was minted.  So
    this assert is untouched, and staying untouched is the claim.
    """
    src = _server_h()
    assert re.search(
        r"_Static_assert\(\s*\(uint64_t\)TLS_TICKET_LIFETIME_S \* 1000u <=\s*"
        r"\(uint64_t\)\(TLS_TICKET_RING - 1\) \* TLS_TICKET_ROTATE_MS",
        src,
    ), "server.h no longer asserts that a ticket cannot outlive its key"
    lifetime_ms = _freastal.TICKET_LIFETIME_S * 1000
    assert lifetime_ms <= (_freastal.TICKET_RING_SLOTS - 1) * _freastal.TICKET_ROTATE_MS


def test_the_exposure_bound_is_asserted_now_that_rotation_left_the_process():
    """The bound that used to hold for free, and now needs a guard.

    While the rotation timer lived in the same process as the keys, "no key is
    held longer than RING*ROTATE" needed no enforcing: a process alive to be
    compromised was a process whose timer was running.  The owner's timer is
    in another process now, so kill -9 on it leaves orphaned workers holding a
    ring nobody will ever rotate -- unbounded key lifetime, which is precisely
    what the ring exists to prevent.  The grace period is the size of that
    hole and it is pinned here rather than left as a number in a comment.
    """
    src = _server_h()
    assert "TLS_TICKET_STALE_GRACE_MS" in src, (
        "nothing bounds how late the ring's owner may be with a rotation"
    )
    assert re.search(
        r"_Static_assert\(\(uint64_t\)TLS_TICKET_STALE_GRACE_MS <= "
        r"\(uint64_t\)TLS_TICKET_ROTATE_MS",
        src,
    ), "the staleness grace is not constrained against the rotation period"


def test_the_seqlock_requires_lock_free_atomics():
    """A seqlock across address spaces needs a real atomic instruction.

    Where the compiler cannot do it in hardware it lowers _Atomic to a
    libatomic call taking a lock in *this* process, which synchronises nothing
    with the other processes mapping the page and would leave torn key reads
    that no behavioural test would show.
    """
    assert re.search(r"_Static_assert\(ATOMIC_INT_LOCK_FREE == 2", _server_h())


# ---------------------------------------------------------------------------
# The owner going away.
#
# The rotation timer used to be in the same process as the keys, so "no key is
# held for longer than RING*ROTATE" needed no enforcing: a process alive to be
# compromised was a process whose timer was running.  It is in another process
# now, and SIGKILL on that one leaves the workers orphaned, serving, and
# holding a ring nobody will ever rotate -- an unbounded key lifetime, which
# is the exact thing rotation exists to prevent.
#
# Reaching that state honestly takes an hour of wall clock, so what is driven
# here instead is a ring built by the test with its deadline already in the
# past.  It exercises the same code the real case would: the worker maps it,
# notices on the first connection, and turns tickets off.
# ---------------------------------------------------------------------------


def _fabricate_ring(path, *, due_ms, grace_ms=0, seq=2, key=b"\xa5" * (_KEY_SIZE - 1)):
    """Write a ring image that is structurally valid and however stale we say."""
    page = 65536  # at least one page on any platform freastal builds for
    buf = bytearray(page)
    buf[: _RING_HDR.size] = _RING_HDR.pack(
        _RING_MAGIC,
        _RING_ABI,
        _freastal.TICKET_RING_SLOTS,
        _KEY_SIZE,
        _freastal.TICKET_ROTATE_MS,
        grace_ms,
        os.getpid(),
        0,
    )
    buf[_SEQ_OFF : _SEQ_OFF + 4] = struct.pack("=I", seq)
    buf[_CUR_OFF : _CUR_OFF + 4] = struct.pack("=i", 0)
    buf[_DUE_OFF : _DUE_OFF + 8] = struct.pack("=Q", due_ms)
    buf[_KEYS_OFF : _KEYS_OFF + _KEY_SIZE] = key + b"\x01"  # ... + live
    path.write_bytes(bytes(buf))
    return path


def _serve_on_ring(certpair, tmp_path, ring_path, requests=2):
    """Run a one-process server on `ring_path` and come back with what it did."""
    cert, key = certpair
    port = free_port()
    src = tmp_path / "stale_app.py"
    src.write_text(
        textwrap.dedent(
            f"""
            import os
            from freastal import _freastal

            def app(environ, start_response):
                body = b"tls-body"
                start_response("200 OK", [("Content-Length", str(len(body)))])
                return [body]

            fd = os.open({str(ring_path)!r}, os.O_RDONLY)
            _freastal.serve(app, host="127.0.0.1", port={port},
                            certfile={cert!r}, keyfile={key!r}, ticket_ring_fd=fd)
            """
        )
    )
    errf = tempfile.NamedTemporaryFile("w+", delete=False)  # noqa: SIM115
    proc = subprocess.Popen(
        [sys.executable, str(src)], stdout=errf, stderr=errf, cwd=str(tmp_path)
    )
    try:
        ctx = tls_context()
        deadline = time.time() + 40
        sessions = []
        while time.time() < deadline and len(sessions) < requests:
            if proc.poll() is not None:
                break
            try:
                sessions.append(request_over_new_connection(port, ctx)[0])
            except (OSError, ssl.SSLError):
                time.sleep(0.2)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
    errf.flush()
    with open(errf.name) as f:
        return sessions, f.read()


def test_a_ring_its_owner_stopped_rotating_turns_tickets_off(certpair, tmp_path):
    """Degrade to "no resumption", not to "unbounded key lifetime".

    And specifically not to "no service": picotls treats a refusal to SEAL a
    ticket as a handshake error, so a guard that lived in the ticket callback
    would have turned a dead supervisor into a server that answers nothing.
    The requests below still have to succeed -- that assertion is the point of
    the test as much as the missing ticket is.
    """
    ring = _fabricate_ring(tmp_path / "stale.ring", due_ms=0, grace_ms=0)
    sessions, log = _serve_on_ring(certpair, tmp_path, ring)

    assert len(sessions) == 2, f"the server stopped serving:\n{log[-2000:]}"
    assert "dropped the shared session-ticket ring" in log, log[-2000:]
    for i, session in enumerate(sessions):
        assert session is None or session.ticket_lifetime_hint == 0, (
            f"connection {i} was handed a ticket sealed under a key from a "
            f"ring that nothing is rotating any more"
        )


def test_a_ring_whose_owner_is_still_rotating_is_used(certpair, tmp_path):
    """The control for the test above: same path, deadline not yet passed.

    Without this, a guard that fired on every ring -- an inverted comparison,
    a clock read that always returned 0 -- would pass the staleness test and
    silently disable resumption for everybody.
    """
    now_ms = time.monotonic_ns() // 1_000_000
    ring = _fabricate_ring(
        tmp_path / "fresh.ring",
        due_ms=now_ms + _freastal.TICKET_ROTATE_MS,
        grace_ms=_freastal.TICKET_ROTATE_MS,
    )
    sessions, log = _serve_on_ring(certpair, tmp_path, ring)

    assert len(sessions) == 2, f"the server stopped serving:\n{log[-2000:]}"
    assert "dropped the shared session-ticket ring" not in log, log[-2000:]
    assert sessions[0] is not None and sessions[0].ticket_lifetime_hint > 0, (
        "a ring whose owner is up to date issued no tickets"
    )


def test_a_ring_promising_a_longer_window_than_this_build_allows_is_refused(
    certpair, tmp_path
):
    """A worker enforces its own exposure ceiling, not the owner's claim.

    rotate_ms and grace_ms come out of the shared region, so an owner could
    publish "I rotate once a week, and give me a month of grace" and the
    staleness guard would never fire.  The worker's compiled-in constants are
    what server.h's arithmetic is written against, so they are the ceiling.
    """
    ring = _fabricate_ring(
        tmp_path / "greedy.ring",
        due_ms=0,
        grace_ms=_freastal.TICKET_ROTATE_MS * 24,
    )
    sessions, log = _serve_on_ring(certpair, tmp_path, ring)
    assert sessions == [], f"the server came up on the greedy ring:\n{log[-2000:]}"
    assert "shared ticket ring" in log, log[-2000:]


def test_the_ring_deadline_is_on_the_same_clock_the_owner_sleeps_on():
    """The deadline is written in C; the sleep meant to meet it is in Python.

    They have to be the same clock or the deadline is meaningless, and "a
    monotonic clock" is not specific enough to get there: CPython's
    time.monotonic() is CLOCK_MONOTONIC on Linux but CLOCK_UPTIME_RAW on
    Apple, where CLOCK_MONOTONIC is a different clock that keeps counting
    through a system sleep.  Getting that wrong made a machine that had been
    asleep declare a perfectly healthy ring stale.
    """
    with attached_ring() as ring:
        due = struct.unpack("=Q", ring.map[_DUE_OFF : _DUE_OFF + 8])[0]
    now_ms = time.monotonic_ns() // 1_000_000
    skew = abs(due - (now_ms + _freastal.TICKET_ROTATE_MS))
    assert skew < 1000, (
        f"the ring's deadline and time.monotonic() are {skew} ms apart, so "
        f"they are not the same clock: the owner's rotation thread sleeps on "
        f"one and every worker judges staleness against the other"
    )


def _ring_smaps_entries():
    """Every /proc/self/smaps block for a ring mapping, keyed by its flags.

    Identified by name: a memfd shows up as /memfd:freastal-ticket-ring
    (deleted), which is also the evidence that the region has no path anyone
    could open by.
    """
    entries, current = [], []
    with open("/proc/self/smaps") as f:
        for line in f:
            if re.match(r"^[0-9a-f]+-[0-9a-f]+ ", line):
                if current:
                    entries.append("".join(current))
                current = [line]
            elif current:
                current.append(line)
    if current:
        entries.append("".join(current))
    return [e for e in entries if "freastal-ticket-ring" in e.splitlines()[0]]


def test_the_region_is_kept_out_of_core_files_and_swap():
    """Not an assertion about the flags passed -- a reading of the mapping.

    A MAP_SHARED file-backed mapping is already outside Linux's default
    coredump_filter of 0x33, so this is better than the anonymous private
    memory the process-local ring lives in, which every core dump includes.
    VM_DONTDUMP ("dd") makes it independent of the filter, and VM_LOCKED
    ("lo") keeps the keys off swap.  The mlock half is best-effort at run time
    -- a container with RLIMIT_MEMLOCK at 0 must still be able to serve -- so
    it is reported rather than required.

    Nothing else maps the ring here on purpose: this creates the ring and
    reads /proc without also mapping it from Python, because a second mapping
    made by something other than freastal would not carry freastal's madvise
    and would be indistinguishable from the real thing having lost it.
    """
    if not sys.platform.startswith("linux"):
        pytest.skip("no /proc/self/smaps here")
    fd = _freastal._ticket_ring_create()
    try:
        entries = _ring_smaps_entries()
    finally:
        os.close(fd)
        _freastal._ticket_ring_destroy()

    if not entries:
        pytest.skip("this build did not get an anonymous memfd for the ring")
    assert len(entries) == 1, f"expected one ring mapping, got:\n{entries}"
    entry = entries[0]
    flags = re.search(r"^VmFlags:(.*)$", entry, re.MULTILINE)
    assert flags, entry
    names = flags.group(1).split()
    assert "dd" in names, (
        f"the ticket ring is not marked VM_DONTDUMP, so a core file of a "
        f"worker could carry the sealing keys:\n{entry}"
    )
    assert "sh" in names, (
        f"the ring is not a shared mapping, so every worker would get a "
        f"copy-on-write snapshot: it would never see a rotation and would "
        f"keep every retired key alive:\n{entry}"
    )
    assert "(deleted)" in entry.splitlines()[0], (
        f"the ring's backing object still has a link somebody could open:\n{entry}"
    )
    assert re.search(r"^Swap:\s+0 kB$", entry, re.MULTILINE), entry
