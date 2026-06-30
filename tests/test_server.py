"""Tests that run against both WSGI and ASGI via the server_url fixture."""

import httpx


def test_hello(server_url):
    r = httpx.get(f"{server_url}/hello")
    assert r.status_code == 200
    assert r.text == "hello"


def test_404(server_url):
    r = httpx.get(f"{server_url}/notexist")
    assert r.status_code == 404


def test_post_echo(server_url):
    r = httpx.post(f"{server_url}/echo", content=b"payload")
    assert r.status_code == 200
    assert r.content == b"payload"


def test_request_header_visible(server_url):
    r = httpx.get(f"{server_url}/header", headers={"X-Test": "freastal"})
    assert r.status_code == 200
    assert r.text == "freastal"


def test_query_string(server_url):
    r = httpx.get(f"{server_url}/query?foo=bar&baz=1")
    assert r.status_code == 200
    assert r.text == "foo=bar&baz=1"


def test_remote_addr(server_url):
    r = httpx.get(f"{server_url}/remote-addr")
    assert r.status_code == 200
    assert r.text == "127.0.0.1"


def test_content_length_auto(server_url):
    r = httpx.get(f"{server_url}/hello")
    assert "content-length" in r.headers
    assert int(r.headers["content-length"]) == len(b"hello")


def test_keep_alive(server_url):
    with httpx.Client() as client:
        for _ in range(10):
            r = client.get(f"{server_url}/hello")
            assert r.status_code == 200
            assert r.text == "hello"
