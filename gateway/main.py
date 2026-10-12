"""API independente do gateway. Execute: python -m gateway.main"""

from getpass import getpass

from fastapi import FastAPI, HTTPException
from cryptography.exceptions import InvalidTag
from pydantic import BaseModel

from gateway import database
from gateway.validation import validate_and_process
from shared.crypto import open_seal, seal

app = FastAPI(title="Gateway de Pagamento Seguro")


class EncryptedMessage(BaseModel):
    salt: str
    ciphertext: str


@app.post("/pay")
def pay(envelope: EncryptedMessage):
    passphrase = getattr(app.state, "payment_passphrase", None)
    if not passphrase:
        raise HTTPException(status_code=503, detail="Gateway não inicializado.")

    try:
        message = open_seal(envelope.model_dump(), passphrase, "payment-request-v1")
    except (ValueError, KeyError, TypeError, UnicodeError, InvalidTag):
        # Erros de autenticação AEAD não expõem conteúdo da mensagem recebida.
        return {"order_id": "UNKNOWN", "status": "BLOCKED", "reason": "INVALID_AUTHENTICATION"}
    result = validate_and_process(message)
    return seal(result, passphrase, "payment-response-v1")


if __name__ == "__main__":
    import uvicorn

    database.init_db()
    secret = getpass("Frase compartilhada com a loja (mínimo 16 caracteres): ")
    if len(secret) < 16:
        raise SystemExit("A frase compartilhada precisa ter no mínimo 16 caracteres.")
    app.state.payment_passphrase = secret
    uvicorn.run(app, host="127.0.0.1", port=8001, proxy_headers=False)
