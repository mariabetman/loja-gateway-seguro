"""Interface de terminal. Execute: python -m client.main"""

from getpass import getpass

import httpx
import qrcode

from client import api


def money(cents):
    return f"R$ {cents // 100},{cents % 100:02d}"


def call_error(exc):
    if isinstance(exc, httpx.HTTPStatusError):
        try:
            detail = exc.response.json().get("detail", "Falha.")
        except ValueError:
            detail = "Resposta inesperada."
        print(f"Erro HTTP {exc.response.status_code}: {detail}")
    else:
        print(f"Falha de comunicação: {exc}")


def register():
    try:
        user = api.register(input("Nome: ").strip(), input("E-mail: ").strip(),
                            getpass("Senha (mínimo 12 caracteres): "))
        print(f"Usuário cadastrado: {user['user_id']}")
        qr = qrcode.QRCode(border=1)
        qr.add_data(user["otpauth_uri"])
        qr.make(fit=True)
        qr.print_ascii(invert=True)
        print("Segredo TOTP (guarde):", user["totp_secret"])
    except httpx.HTTPError as exc:
        call_error(exc)


def login():
    try:
        data = api.login_password(input("E-mail: ").strip(), getpass("Senha: "))
        print("Senha aceita. Digite o código do autenticador:")
        result = api.login_totp(data["challenge"], input("TOTP (6 dígitos): ").strip())
        print("Login realizado.")
        return result["access_token"]
    except httpx.HTTPError as exc:
        call_error(exc)
        return None


def print_cart(cart):
    for item in cart["items"]:
        print(f"{item['product_id']} - {item['name']}: {item['quantity']} × "
              f"{money(item['unit_price_cents'])}")
    print("Total:", money(cart["total_cents"]))


def print_order(order):
    print(f"Pedido: {order['order_id']} | {order['status']} | {money(order['total_cents'])}")
    if order.get("reason"):
        print("Motivo:", order["reason"])
    print("Localização aproximada registrada:", order["location"])


def main():
    token = None
    while True:
        print("\n=== LOJA VIRTUAL SEGURA ===")
        if token is None:
            print("1. Cadastro | 2. Login | 0. Sair")
        else:
            print("3. Perfil | 4. Produtos | 5. Carrinho | 6. Alterar carrinho")
            print("7. Comprar | 8. Pedidos | 9. Localização | 10. Logout | 0. Sair")
        option = input("Opção: ").strip()
        if option == "0":
            if token:
                try:
                    api.logout(token)
                except httpx.HTTPError:
                    pass
            break
        if token is None:
            if option == "1":
                register()
            elif option == "2":
                token = login()
            else:
                print("Opção inválida.")
            continue
        try:
            if option == "3":
                print(api.get_profile(token))
            elif option == "4":
                for product in api.products(token):
                    print(product["id"], product["name"], money(product["price_cents"]))
            elif option == "5":
                print_cart(api.cart(token))
            elif option == "6":
                product = input("Código do produto: ").strip().upper()
                quantity = int(input("Quantidade (0 para remover): "))
                print_cart(api.set_quantity(token, product, quantity))
            elif option == "7":
                print_order(api.checkout(token))
            elif option == "8":
                for order in api.orders(token):
                    print_order(order)
            elif option == "9":
                print(api.get_location(token))
            elif option == "10":
                api.logout(token)
                token = None
                print("Sessão encerrada.")
            else:
                print("Opção inválida.")
        except httpx.HTTPError as exc:
            call_error(exc)
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 401:
                token = None
        except ValueError:
            print("Informe uma quantidade numérica válida.")


if __name__ == "__main__":
    main()
