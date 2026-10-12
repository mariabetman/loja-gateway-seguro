"""API da loja. Execute: python -m store.main"""

from getpass import getpass

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from store import database
from store.auth import (AuthenticationError, DuplicateEmailError, CHALLENGE_TTL, SESSION_TTL,
                        current_user, finish_login, logout, register_user, start_login)
from store.checkout import CartError, cart, checkout, order_detail, orders, products, set_quantity
from store.models import (PasswordLoginIn, PasswordLoginOut, RegistrationIn, RegistrationOut,
                          TotpLoginIn, TotpLoginOut, UserOut)
from store.security import init_or_verify_master_passphrase
from shared.geo import GeoError, lookup_ip

app = FastAPI(title="Loja Virtual Segura")


class CartUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")  # dados de localização enviados pelo cliente são ignorados
    product_id: str
    quantity: int = Field(ge=0, le=100)


class CheckoutIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    # Campo intencionalmente vazio: total e localização vêm exclusivamente do servidor.


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _secret(request: Request, key: str) -> str:
    value = getattr(request.app.state, key, None)
    if not value:
        raise HTTPException(503, "Servidor não inicializado.")
    return value


def _bearer(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Token ausente.")
    token = authorization[7:].strip()
    if not token or " " in token:
        raise HTTPException(401, "Token inválido.")
    return token


def require_user(request: Request, token: str = Depends(_bearer)) -> UserOut:
    try:
        return current_user(token, _ip(request))
    except AuthenticationError as exc:
        raise HTTPException(401, str(exc)) from exc


@app.post("/register", response_model=RegistrationOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegistrationIn, request: Request):
    try:
        return register_user(payload, _secret(request, "master_passphrase"))
    except DuplicateEmailError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/login/password", response_model=PasswordLoginOut)
def login_password(payload: PasswordLoginIn, request: Request):
    try:
        challenge = start_login(str(payload.email), payload.password, _ip(request))
    except AuthenticationError as exc:
        raise HTTPException(401, str(exc)) from exc
    return PasswordLoginOut(challenge=challenge, expires_in=CHALLENGE_TTL)


@app.post("/login/totp", response_model=TotpLoginOut)
def login_totp(payload: TotpLoginIn, request: Request):
    try:
        token = finish_login(payload.challenge, payload.code, _ip(request),
                             _secret(request, "master_passphrase"))
    except AuthenticationError as exc:
        raise HTTPException(401, str(exc)) from exc
    return TotpLoginOut(access_token=token, expires_in=SESSION_TTL)


@app.get("/me", response_model=UserOut)
def me(user: UserOut = Depends(require_user)):
    return user


@app.get("/me/location")
def my_location(request: Request, user: UserOut = Depends(require_user)):
    try:
        return lookup_ip(_ip(request))
    except GeoError as exc:
        raise HTTPException(503, str(exc)) from exc


@app.post("/logout", status_code=204)
def end_session(request: Request, token: str = Depends(_bearer)):
    require_user(request, token)
    logout(token)


@app.get("/products")
def list_products(user: UserOut = Depends(require_user)):
    return products()


@app.get("/cart")
def show_cart(user: UserOut = Depends(require_user)):
    return cart(user.user_id)


@app.put("/cart")
def update_cart(payload: CartUpdate, user: UserOut = Depends(require_user)):
    try:
        return set_quantity(user.user_id, payload.product_id, payload.quantity)
    except CartError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/checkout")
def finalize(payload: CheckoutIn, request: Request,
             user: UserOut = Depends(require_user), token: str = Depends(_bearer)):
    try:
        return checkout(user.user_id, token, _ip(request),
                        _secret(request, "payment_passphrase"))
    except (CartError, AuthenticationError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except GeoError as exc:
        raise HTTPException(503, str(exc)) from exc


@app.get("/orders")
def list_orders(user: UserOut = Depends(require_user)):
    return orders(user.user_id)


@app.get("/orders/{order_id}")
def get_order(order_id: str, user: UserOut = Depends(require_user)):
    try:
        return order_detail(user.user_id, order_id)
    except CartError as exc:
        raise HTTPException(404, str(exc)) from exc


if __name__ == "__main__":
    import uvicorn
    database.init_db()
    master = getpass("Frase-mestra do cadastro (mínimo 16 caracteres): ")
    if len(master) < 16:
        raise SystemExit("Frase-mestra muito curta.")
    try:
        init_or_verify_master_passphrase(master)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    payment = getpass("Frase compartilhada com o gateway (mínimo 16 caracteres): ")
    if len(payment) < 16:
        raise SystemExit("Frase do gateway muito curta.")
    app.state.master_passphrase = master
    app.state.payment_passphrase = payment
    uvicorn.run(app, host="127.0.0.1", port=8000, proxy_headers=False)
