"""API HTTP da loja. Inicie usando: python -m store.main"""

from getpass import getpass

from fastapi import FastAPI, HTTPException, Request, status

from store import database
from store.auth import DuplicateEmailError, register_user
from store.models import RegistrationIn, RegistrationOut
from store.security import init_or_verify_master_passphrase

app = FastAPI(title="Loja Segura", version="0.1.0")


@app.post("/register", response_model=RegistrationOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegistrationIn, request: Request) -> RegistrationOut:
    master_passphrase = getattr(request.app.state, "master_passphrase", None)
    if master_passphrase is None:
        raise HTTPException(
            status_code=503,
            detail="Servidor não inicializado; execute python -m store.main.",
        )
    try:
        return register_user(payload, master_passphrase)
    except DuplicateEmailError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


if __name__ == "__main__":
    import uvicorn

    database.init_db()
    passphrase = getpass("Frase-mestra da loja (mínimo de 16 caracteres): ")
    if len(passphrase) < 16:
        raise SystemExit("A frase-mestra deve ter ao menos 16 caracteres.")
    try:
        init_or_verify_master_passphrase(passphrase)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    # Apenas no processo do servidor; não é variável global nem variável de ambiente do cliente.
    app.state.master_passphrase = passphrase
    uvicorn.run(app, host="127.0.0.1", port=8000)
