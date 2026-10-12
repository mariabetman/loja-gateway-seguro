"""Interface de terminal do cliente. Inicie usando: python -m client.main"""

from getpass import getpass

import httpx
import qrcode

from client import api


def register_user() -> None:
    print("\n=== Cadastro de usuário ===")
    name = input("Nome: ").strip()
    email = input("E-mail: ").strip()
    password = getpass("Senha (mínimo de 6 caracteres): ")

    try:
        data = api.register(name, email, password)
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json().get("detail", "Erro de cadastro")
        except ValueError:
            detail = "Resposta inesperada do servidor"
        print(f"Cadastro não realizado ({exc.response.status_code}): {detail}")
        return
    except httpx.RequestError as exc:
        print(f"Não foi possível conectar à loja: {exc}")
        return

    print(f"\nCadastro realizado! ID: {data['user_id']}")
    print("Configure agora o TOTP no seu aplicativo autenticador.")
    print("Escaneie o QR Code abaixo ou digite manualmente a chave:")
    qr = qrcode.QRCode(border=1)
    qr.add_data(data["otpauth_uri"])
    qr.make(fit=True)
    qr.print_ascii(invert=True)
    print(f"Chave TOTP (mostrada somente agora): {data['totp_secret']}")
    print("A validação do código TOTP será adicionada na próxima etapa.\n")


def main() -> None:
    while True:
        print("\n=== LOJA VIRTUAL SEGURA ===")
        print("1. Cadastrar usuário")
        print("0. Sair")
        choice = input("Escolha: ").strip()
        if choice == "1":
            register_user()
        elif choice == "0":
            break
        else:
            print("Opção inválida ou ainda não implementada.")


if __name__ == "__main__":
    main()
