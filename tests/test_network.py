"""Fronteira de confiança do túnel e configuração do cliente."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from client.api import validate_store_url
from store.network import observed_ip


def request(peer="127.0.0.1", headers=(), tunnel_host="random.internal"):
    return Request({"type": "http", "client": (peer, 1234),
                    "headers": [(k.encode(), v.encode()) for k, v in headers],
                    "app": SimpleNamespace(state=SimpleNamespace(tunnel_host=tunnel_host))})


VALID = [("host", "random.internal"), ("cf-connecting-ip", "8.8.8.8"),
         ("x-forwarded-proto", "https")]


def test_local_mode_ignores_all_forwarded_headers():
    assert observed_ip(request(headers=VALID, tunnel_host=None)) == "127.0.0.1"


def test_tunnel_uses_cloudflare_ip_and_ignores_xff():
    assert observed_ip(request(headers=VALID + [("x-forwarded-for", "1.1.1.1")])) == "8.8.8.8"


@pytest.mark.parametrize("peer,headers", [
    ("8.8.4.4", VALID),
    ("127.0.0.1", []),
    ("127.0.0.1", [("host", "wrong.internal")] + VALID[1:]),
    ("127.0.0.1", [("host", "inválido.internal")] + VALID[1:]),
    ("127.0.0.1", VALID + [("host", "random.internal")]),
    ("127.0.0.1", VALID + [("cf-connecting-ip", "1.1.1.1")]),
    ("127.0.0.1", [VALID[0], ("cf-connecting-ip", "127.0.0.1"), VALID[2]]),
    ("127.0.0.1", [VALID[0], ("cf-connecting-ip", "8.8.8.8, 1.1.1.1"), VALID[2]]),
    ("127.0.0.1", VALID[:2] + [("x-forwarded-proto", "http")]),
    ("127.0.0.1", [VALID[0], VALID[2]]),
])
def test_tunnel_rejects_untrusted_or_ambiguous_context(peer, headers):
    with pytest.raises(HTTPException):
        observed_ip(request(peer, headers))


@pytest.mark.parametrize("url", ["http://example.com", "https://user:pass@example.com",
                                "https://example.com/path", "https://example.com?ip=1",
                                "ftp://example.com", "https://example.com:99999"])
def test_client_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):
        validate_store_url(url)


def test_client_accepts_https_and_local_http():
    assert validate_store_url("https://example.trycloudflare.com/") == "https://example.trycloudflare.com"
    assert validate_store_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"


def test_ipv4_client_keeps_tls_and_disables_environment_proxies(monkeypatch):
    import httpx
    from client import api
    original_transport = httpx.HTTPTransport
    captured = {}

    def transport(**kwargs):
        captured.update(kwargs)
        return original_transport(**kwargs)

    class Client:
        def __init__(self, **kwargs):
            captured.update(kwargs)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            captured["transport"].close()
        def request(self, method, path, **kwargs):
            return httpx.Response(200, json={"ok": True}, request=httpx.Request(method, "https://example.com"))

    monkeypatch.setattr(httpx, "HTTPTransport", transport)
    monkeypatch.setattr(httpx, "Client", Client)
    assert api._request("GET", "/me") == {"ok": True}
    assert captured["local_address"] == "0.0.0.0" and captured["trust_env"] is False
    assert "verify" not in captured
