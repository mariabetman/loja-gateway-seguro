# Documentação do código

Esta documentação descreve os módulos efetivamente implementados, e não substitui o relatório acadêmico.

## Arquitetura

**Iniciador (`main.py`)**: fluxo padrão integrado; inicia loja e gateway em processos separados, encaminha as frases por pipes locais, cria o túnel, configura o cliente e encerra os processos ao sair. O modo `--local` dispensa o túnel. A integração não substitui as mensagens HTTP protegidas entre loja e gateway.

**Cliente (`client/`)**: menus no terminal em `main.py` e operações HTTP em `api.py`. O token fica apenas na memória do processo.

**Loja (`store/`)**: `main.py` publica a API FastAPI; `models.py` define os esquemas; `database.py` cria e migra o SQLite; `auth.py` executa cadastro, verificação de senha, TOTP, sessão e logout; `security.py` faz hashing Argon2id; `totp.py` calcula códigos RFC 6238; `checkout.py` lida com catálogo, carrinho, pedidos e envio ao gateway.

**Gateway (`gateway/`)**: `main.py` recebe os envelopes AES-GCM, valida e cifra as respostas. `validation.py` verifica prova de autenticação com TOTP, pedido, catálogo, quantias, IP, nonce e timestamp. `database.py` guarda transações e nonces, em arquivo diferente do banco da loja.

**Compartilhado (`shared/`)**: `crypto.py` define a cifragem e a derivação; `geo.py` consulta a base IP2Location; `products.py` guarda preços oficiais usados também para a validação independente do gateway. Compartilhar módulos de código **não compartilha estado de sessão, bancos, chaves ou IVs** entre processos.

## Endpoints da loja

| Método | Rota | Finalidade |
| --- | --- | --- |
| POST | `/register` | Cria usuário, gera segredo TOTP e URI do QR Code |
| POST | `/login/password` | Verifica senha, cria desafio de até 5 minutos |
| POST | `/login/totp` | Confere segundo fator; devolve token Bearer |
| GET | `/me` | Obtém usuário autenticado |
| GET | `/me/location` | Mostra contexto de IP observado |
| POST | `/logout` | Revoga o token |
| GET | `/products` | Lista produtos |
| GET | `/cart` | Consulta carrinho |
| PUT | `/cart` | Define quantidade de produto; zero remove |
| POST | `/checkout` | Calcula pedido no servidor e envia ao gateway |
| GET | `/orders` | Histórico de pedidos |
| GET | `/orders/{order_id}` | Detalhes do pedido |

`/me`, localização, catálogo, carrinho, checkout e pedidos exigem `Authorization: Bearer <token>`.

## Endpoint do gateway

`POST /pay`: recebe somente `{ "salt": "base64", "ciphertext": "base64" }` e abre a mensagem AES-GCM derivando chave/IV com Scrypt. A resposta normal, incluindo `APPROVED` ou `BLOCKED`, é **igualmente cifrada** com outro salt aleatório. Se a mensagem falhar na autenticação AEAD, retorna apenas `BLOCKED/INVALID_AUTHENTICATION` sem decifrar dados não confiáveis.

A mensagem protegida contém `order_id`, `user_id`, `items` (produto, quantidade e preço), `amount`, `amount_cents`, `currency`, `nonce`, `timestamp`, `client_ip`, `location` e `auth` (prova de senha e TOTP confirmados pela loja, horário e IP).

O retorno protegido contém `order_id`, `status`, `timestamp`, `nonce` e, em caso de recusa, `reason`. A loja confere que `order_id` e `nonce` correspondem ao pedido enviado.

## Criptografia e segredos

- **Senha:** Argon2id (hash, não cifragem reversível).
- **Segredo TOTP persistido:** AES-256-GCM usando chave/IV derivados de uma frase-mestra da loja por Scrypt com salt aleatório de 16 bytes. O segredo não é guardado em claro.
- **Loja ↔ gateway:** mesma derivação Scrypt com frase compartilhada digitada de forma independente nos dois processos, salt aleatório novo para cada cifragem, AES-GCM com dados autenticados associados (purpose). Salt viaja em claro; chaves e IVs não são transmitidos ou escritos em arquivos.
- **Proteção de replay:** nonce de transação independente do IV AES-GCM e restrição de timestamp ±120 segundos. O gateway registra cada nonce em SQLite (`UNIQUE`); já utilizado = `INVALID_NONCE`.
- **TOTP:** RFC 6238 / HMAC-SHA1, seis dígitos, período de 30 segundos, tolerância de um intervalo. Salva último contador aceito para impedir reutilização.
- **Sessão:** identificador gerado aleatoriamente, hash SHA-256 no banco, duração de uma hora e vínculo ao IP observado.
- **Regra contextual:** alteração do país anteriormente observado bloqueia o novo login; geolocalização nunca conta como segundo fator. Cliente não fornece IP aceito como verdade.

## Regras de valor

Preços são representados internamente em **centavos inteiros**, evitando `float` no cálculo do total. O formato monetário decimal no protocolo atende às exigências de representação (`amount`, `unit_price`). O gateway verifica esses valores contra os centavos e compara preços e produtos com o catálogo oficial em `shared/products.py`.

No processo único da loja, alteração e checkout usam um bloqueio por usuário. Durante o pagamento, mudanças no carrinho e outra finalização do mesmo usuário são recusadas com uma mensagem para aguardar. O bloqueio em memória é liberado mesmo em caso de falha; outros usuários continuam utilizando seus carrinhos.

O gateway recusa um `order_id` já registrado com `DUPLICATE_ORDER`, mesmo com nonce novo. A consulta e o registro ocorrem na mesma transação SQLite (`BEGIN IMMEDIATE`), impedindo duas aprovações simultâneas para o mesmo pedido. A regra permanece após reiniciar o serviço; um pedido já registrado como bloqueado também não pode ser reapresentado com o mesmo identificador.

Se a resposta do gateway se perder ou for inválida, a loja registra `ERROR`, com motivo `GATEWAY_UNAVAILABLE_OR_INVALID_RESPONSE`, e preserva o carrinho. Isso indica resultado não confirmado, não uma recusa do gateway. Não há consulta ou reenvio automático do pagamento; conferir o resultado no gateway é uma operação manual. Uma nova compra cria outro pedido e pode duplicar uma operação já aprovada cuja resposta se perdeu.

## Testes e demonstrações

- `tests/test_registration.py`: proteção de senha e TOTP, validação de cadastro.
- `tests/test_launcher.py`: processos independentes, inicialização, encerramento e porta ocupada.
- `tests/test_network.py`: validação da origem do túnel, cabeçalhos, URL e transporte IPv4.
- `tests/test_authentication.py`: login e sessão, limites do desafio, reutilização do código.
- `tests/test_payments.py`: compra integrada, gateway, valores adulterados, replay, timestamp, localização ignorada, bloqueio contextual e adaptador IP2Location simulado.
- `scripts/demo_attacks.py`: quatro demonstrações via HTTP entre os servidores executados.
- `scripts/geo_demo.py`: consulta a um IP público usando o banco IP2Location **real** instalado pelo grupo.

## Limitações do protótipo

**Modo local (`python main.py --local`):** o tráfego cliente–loja usa HTTP em localhost. O IP `127.0.0.1` é identificado como `LOOPBACK`, com país `LOCAL`, sem localização geográfica real.

**Modo túnel (`python main.py`):** o cliente IPv4 acessa a loja por HTTPS. O HTTPS termina na Cloudflare, que encaminha a requisição pelo túnel até o processo local; o último salto até a loja usa HTTP em loopback. `store/network.py` exige origem de loopback, o Host aleatório configurado pelo iniciador, um único `CF-Connecting-IP` público e `X-Forwarded-Proto: https`; `X-Forwarded-For` é ignorado. Essa validação depende da confiança na Cloudflare e na máquina local; não autentica criptograficamente o processo do túnel. O modo depende de Internet e do serviço de túnel.

**Limitações e cuidados comuns aos dois modos:**

- Não contém adquirência ou cobrança real.
- O controle de tentativas de autenticação é parcial: há limite de TOTP por desafio, mas não há limitação global de tentativas por conta ou origem. HTTPS não resolve essa limitação.
- Consultas a IPs públicos exigem a base DB11 em `data/ip2location/IP2LOCATION-LITE-DB11.BIN`, com cobertura do IP consultado. O modo local funciona sem a base por utilizar loopback.
- O comprovante de autenticação encaminhado ao gateway é uma **asserção autenticada da loja**; o gateway não recebe a senha nem o segredo TOTP do usuário.
- Os arquivos `data/*.db` não devem ser versionados nem expostos; o envelope cifrado salvo em `orders` serve à demonstração de replay.
- A validação de região/cidade depende da precisão estimada do IP2Location e não deve ser tratada como GPS.
