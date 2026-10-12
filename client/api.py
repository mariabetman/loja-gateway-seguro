"""Cliente HTTP usado pelos menus no terminal."""

import httpx

STORE_URL = "http://127.0.0.1:8000"


def _request(method: str, path: str, *, data: dict | None = None,
             token: str | None = None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    with httpx.Client(base_url=STORE_URL, timeout=15) as client:
        response = client.request(method, path, json=data, headers=headers)
        response.raise_for_status()
        return response.json() if response.content else {}


def register(name, email, password):
    return _request("POST", "/register", data={"name": name, "email": email, "password": password})


def login_password(email, password):
    return _request("POST", "/login/password", data={"email": email, "password": password})


def login_totp(challenge, code):
    return _request("POST", "/login/totp", data={"challenge": challenge, "code": code})


def get_profile(token):
    return _request("GET", "/me", token=token)


def get_location(token):
    return _request("GET", "/me/location", token=token)


def products(token):
    return _request("GET", "/products", token=token)


def cart(token):
    return _request("GET", "/cart", token=token)


def set_quantity(token, product_id, quantity):
    return _request("PUT", "/cart", token=token,
                    data={"product_id": product_id, "quantity": quantity})


def checkout(token):
    return _request("POST", "/checkout", token=token, data={})


def orders(token):
    return _request("GET", "/orders", token=token)


def logout(token):
    return _request("POST", "/logout", token=token)
