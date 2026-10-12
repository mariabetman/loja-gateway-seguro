# Loja Segura — Etapa 1: Cadastro

Projeto didático da disciplina de Segurança de Redes. **Esta etapa implementa apenas o cadastro** e a preparação do segredo TOTP. Login, gateway, geolocalização e pagamentos serão desenvolvidos nas próximas etapas.

## Requisitos

Python 3.11+.

## Instalação

No diretório raiz do projeto:

```sh
python -m venv .venv
```

Ative o ambiente virtual:

- Windows (PowerShell): `.venv\Scripts\Activate.ps1`
- macOS/Linux: `source .venv/bin/activate`

```sh
python -m pip install -r requirements.txt
```

## Execução

Em **um primeiro terminal**, execute:

```sh
python -m store.main
```

Digite uma frase-mestra forte (ao menos 16 caracteres). **Guarde-a em local seguro:** será necessário digitar exatamente a mesma frase-mestra nas próximas inicializações. Ela não é gravada em texto puro no banco ou em variáveis de ambiente. O programa não funcionará ao ser iniciado diretamente com `uvicorn store.main:app`, pois a frase-mestra é solicitada pelo lançador interativo.

Em **um segundo terminal**, com ambiente virtual ativado e na raiz do projeto, execute:

```sh
python -m client.main
```

Escolha `1` e informe nome, e-mail e uma senha com pelo menos 6 caracteres. Depois do cadastro, o terminal mostrará um QR Code e o segredo TOTP **apenas uma vez**. Cadastre-o em um aplicativo autenticador.

A API está em `http://127.0.0.1:8000/docs` para facilitar os testes. Por simplicidade, **não utilize este protótipo pela Internet ou com senhas reais**: a conexão HTTP local não tem TLS. O acesso inicial foi restringido a `127.0.0.1`.

## Testes

```sh
python -m pytest -q
```

## Armazenamento e segurança

- `data/store.db` é criado automaticamente, e não deve ser versionado.
- Senhas: Argon2id com salt e parâmetros incluídos no hash.
- TOTP: segredo aleatório Base32, cifrado com AES-GCM. Para cada cifragem, Scrypt deriva uma chave e um IV exclusivos a partir da frase-mestra digitada pelo operador e de um salt aleatório novo. A consulta por e-mail é autenticada como dado associado (AAD).
- O salt de derivação fica em claro; nem a frase-mestra, nem a chave de cifragem ficam no arquivo ou no código.
- O segredo TOTP é exposto **somente na resposta do cadastro**, para ser provisionado no aplicativo autenticador. Sua confirmação e seu uso no login serão implementados na etapa 2.
- A frase-mestra é mantida em memória **somente no processo do servidor da loja** durante sua execução. Essa proteção é diferente do protocolo futuro entre loja e gateway.
- **Nunca reutilize um salt de cifragem com esta implementação AES-GCM**, pois ela deriva o mesmo IV para um salt e uma frase-mestra dados.

## Observação de arquitetura

Os diretórios `gateway/`, `scripts/`, `data/ip2location/` e `docs/` estão reservados para as próximas etapas. O código atual ainda não implementa essas funcionalidades.
