"""Comunicação HTTP entre o programa CLI e a API da loja."""

import httpx

STORE_URL = "http://127.0.0.1:8000"


def register(name: str, email: str, password: str) -> dict:
    with httpx.Client(base_url=STORE_URL, timeout=10) as client:
        response = client.post("/register", json={
            "name": name,
            "email": email,
            "password": password,
        })
        response.raise_for_status()
        return response.json()
