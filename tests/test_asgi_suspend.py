"""ASGI apps that suspend must be resumed by the libuv <-> asyncio bridge.

uv_check_t fires once per libuv iteration, and libuv blocks in its poll phase
whenever no socket is ready. Without something keeping the loop iterating,
asyncio stops being stepped and a suspended task hangs until unrelated traffic
happens to wake the loop.
"""

import time

import httpx
import pytest


@pytest.mark.parametrize("n", [1, 2, 3, 10, 50])
def test_repeated_suspension_completes(asgi_url, n):
    r = httpx.get(f"{asgi_url}/await-chain/{n}", timeout=10)
    assert r.status_code == 200
    assert r.content == b"chained"


def test_sleep_resumes_and_honours_the_delay(asgi_url):
    start = time.perf_counter()
    r = httpx.get(f"{asgi_url}/sleep/0.25", timeout=10)
    elapsed = time.perf_counter() - start
    assert r.status_code == 200
    assert r.content == b"slept"
    assert elapsed >= 0.24, f"returned early after {elapsed:.3f}s"
    assert elapsed < 3.0, f"took {elapsed:.3f}s; loop is not waking promptly"


def test_zero_sleep_resumes(asgi_url):
    r = httpx.get(f"{asgi_url}/sleep/0", timeout=10)
    assert r.content == b"slept"


def test_socket_io_resumes(asgi_url):
    r = httpx.get(f"{asgi_url}/await-io", timeout=10)
    assert r.content == b"pong"


def test_suspending_requests_do_not_need_unrelated_traffic(asgi_url):
    """A single in-flight suspending request, with nothing else touching the
    server, is exactly the case that used to deadlock."""
    with httpx.Client(base_url=asgi_url, timeout=10) as client:
        for _ in range(5):
            assert client.get("/await-chain/20").content == b"chained"


def test_keep_alive_mixes_sync_and_suspending_requests(asgi_url):
    with httpx.Client(base_url=asgi_url, timeout=10) as client:
        for _ in range(3):
            assert client.get("/hello").content == b"hello"
            assert client.get("/await-chain/5").content == b"chained"
            assert client.get("/sleep/0.01").content == b"slept"
            assert client.get("/await-io").content == b"pong"


def test_pipelined_requests_that_suspend(asgi_url):
    """Pipelined requests whose handlers suspend must all be answered.

    This is the interaction between HTTP pipelining and the asyncio wakeups:
    a pipelined request is dispatched from a write completion, which libuv
    runs in its pending phase -- before it computes the poll timeout. An app
    that finishes inline is safe (its uv_write puts the stream on libuv's
    pending queue, forcing a zero timeout), but one that suspends leaves only
    a Task on loop._ready with nothing to force the next iteration.
    """
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(asgi_url)
    n = 3
    req = b"GET /sleep/0.01 HTTP/1.1\r\nHost: localhost\r\n\r\n" * n

    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.sendall(req)
        sock.settimeout(3.0)
        data = b""
        try:
            while data.count(b"HTTP/1.1 200") < n:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except TimeoutError:
            pass

    assert data.count(b"HTTP/1.1 200") == n
    assert data.count(b"slept") == n


def _read_responses(sock, count, timeout=10.0):
    """Read from sock until `count` status lines have arrived, or we stall."""
    sock.settimeout(timeout)
    data = b""
    try:
        while data.count(b"HTTP/1.1 200") < count:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except TimeoutError:
        pass
    return data


def test_request_arriving_while_a_response_is_in_flight(asgi_url):
    """A second request that lands mid-flight must not be answered early.

    Reading is left armed across dispatch, so the bytes of request 2 arrive
    while request 1 is still suspended.  They have to sit in read_buf until
    request 1's response has been written: answering request 2 first would
    interleave two responses on one connection.
    """
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(asgi_url)
    with socket.create_connection((parsed.hostname, parsed.port), timeout=10) as sock:
        sock.sendall(b"GET /sleep/0.4 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        time.sleep(0.15)  # request 1 is now dispatched and suspended
        sock.sendall(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data = _read_responses(sock, 2)

    assert data.count(b"HTTP/1.1 200") == 2, data
    assert data.index(b"slept") < data.index(b"hello"), data


def test_pipelining_past_the_read_buffer_while_suspended(asgi_url):
    """Pipelining more than READ_BUF_SIZE while a response is outstanding.

    read_buf is 16KB and cannot be drained until the suspended request
    answers, so the server has to stop reading at the buffer boundary and
    resume once there is room.  Every request must still be answered.
    """
    import socket
    import threading
    from urllib.parse import urlparse

    parsed = urlparse(asgi_url)
    n = 600  # 600 * 41 bytes ~= 24KB, comfortably past the 16KB read buffer
    flood = b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n" * n

    with socket.create_connection((parsed.hostname, parsed.port), timeout=20) as sock:
        sock.sendall(b"GET /sleep/0.2 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        time.sleep(0.05)
        # Send from a thread: the server stops reading at the buffer boundary,
        # so a blocking sendall of 24KB must not be able to wedge the test.
        sender = threading.Thread(target=sock.sendall, args=(flood,), daemon=True)
        sender.start()
        data = _read_responses(sock, n + 1, timeout=20.0)
        sender.join(timeout=10)

    assert data.count(b"HTTP/1.1 200") == n + 1, data.count(b"HTTP/1.1 200")
    assert data.count(b"hello") == n
    assert data.count(b"slept") == 1


def test_peer_reset_while_a_response_is_in_flight(asgi_url):
    """An RST arriving mid-flight must not close the handle twice.

    on_read can now fire with a write outstanding.  Closing from there would
    complete that write with UV_ECANCELED and on_write would close a second
    time, which libuv aborts on -- taking the whole worker with it.
    """
    import socket
    import struct
    from urllib.parse import urlparse

    parsed = urlparse(asgi_url)
    for _ in range(5):
        sock = socket.create_connection((parsed.hostname, parsed.port), timeout=5)
        # SO_LINGER with a zero timeout makes close() send RST, not FIN.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.sendall(b"GET /sleep/0.2 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        time.sleep(0.05)
        sock.close()

    # The worker must still be serving.
    time.sleep(0.4)
    r = httpx.get(f"{asgi_url}/hello", timeout=10)
    assert r.status_code == 200
    assert r.content == b"hello"
