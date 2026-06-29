"""ASGI-specific tests."""
import json
import httpx


def test_scope_fields(asgi_url):
    """Verify freastal populates the ASGI scope correctly."""
    r = httpx.get(f"{asgi_url}/scope?x=1")
    assert r.status_code == 200
    data = json.loads(r.content)
    assert data["method"] == "GET"
    assert data["path"] == "/scope"
    assert data["query_string"] == "x=1"
