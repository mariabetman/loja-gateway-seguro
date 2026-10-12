# Loja Virtual Segura — INE5680

Projeto Python com três programas: **cliente de terminal**, **API da loja** e **gateway de pagamento independente**. A loja e o gateway usam bancos SQLite separados. Nenhum pagamento real é processado.

## 1. Requisitos e instalação

- Python **3.11 ou superior**.
- Aplicativo compatível com TOTP (Google Authenticator, Microsoft Authenticator etc.).
- A biblioteca `IP2Location` e seu arquivo BIN oficial para consultar **IPs públicos** (seção 5).

No **Windows / PowerShell**, abra a pasta do projeto e execute:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

No Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

> Caso o Windows bloqueie a ativação do ambiente, execute os comandos com `.\.venv\Scripts\python.exe` no lugar de `python`.

## 2. Executar a aplicação (três terminais)

Todos os terminais devem estar **na pasta raiz do projeto**, com o mesmo ambiente virtual ativado.

**Terminal 1 — gateway (porta 8001):**

```powershell
python -m gateway.main
```

Digite uma frase compartilhada com pelo menos 16 caracteres, por exemplo uma frase forte criada exclusivamente para o exercício. **Guarde essa frase**: a mesma deverá ser digitada na loja.

**Terminal 2 — loja (porta 8000):**

```powershell
python -m store.main
```

Digite:

1. A **frase-mestra da loja** (no mínimo 16 caracteres): protege os segredos TOTP no SQLite; use sempre a mesma ao reiniciar com o mesmo banco.
2. A **frase compartilhada com o gateway**: use exatamente a mesma digitada no terminal 1.

As frases não são chaves estáticas armazenadas no código nem variáveis de ambiente. Chaves e IVs temporários são derivados a partir delas e de salts aleatórios por cifragem.

**Terminal 3 — cliente CLI:**

```powershell
python -m client.main
```

### Fluxo de uso

1. Escolha **1 — Cadastro** e informe nome, e-mail e senha (mínimo 12 caracteres).
2. Escaneie o QR Code exibido pelo terminal ou cadastre manualmente o segredo TOTP no aplicativo autenticador. O segredo aparece somente nessa operação.
3. Escolha **2 — Login**; informe e-mail e senha e depois o código de **6 dígitos** mostrado no celular.
4. Escolha **4 — Produtos** para consultar o catálogo e **6 — Alterar carrinho** para escolher um produto (`P01`, `P02` ou `P03`) e uma quantidade.
5. Escolha **5 — Carrinho** para visualizar os valores e **7 — Comprar** para enviar a operação cifrada ao gateway.
6. Veja a aprovação ou o bloqueio; a opção **8 — Pedidos** mostra o histórico. A opção **9 — Localização** exibe o contexto IP observado pelo servidor.
7. **10 — Logout** encerra a sessão.

O cliente nunca define o preço final nem a localização; a loja obtém preços do seu catálogo e geolocalização a partir do IP da conexão.

**IMPORTANTE:** para a demonstração local, os servidores aceitam apenas `127.0.0.1`; não exponha estes serviços à Internet. O tráfego cliente–loja é HTTP puro para facilitar o laboratório: **não use senhas reais**. Para acesso remoto, são necessários TLS e configuração de rede apropriada.

## 3. Testes automatizados

```powershell
python -m pytest -q
```

Os testes cobrem cadastro, senhas, TOTP, sessão, carrinho, compra, gateways, adulteração, replay, timestamp, checagem de valores, contexto IP e a integração do adaptador IP2Location (com dados simulados para evitar distribuir o banco BIN).

## 4. Demonstração dos ataques exigidos

Com os servidores ligados e um usuário já cadastrado, abra **outro terminal**:

```powershell
python -m scripts.demo_attacks
```

O programa solicita o e-mail, a senha do usuário, a frase compartilhada loja–gateway (somente para decifrar e **inspecionar a resposta durante a demonstração**) e um código TOTP válido. Ele realiza uma compra de teste e mostra:

- **C. TOTP inválido:** o servidor recusa a tentativa com código incorreto.
- **D. Localização falsa:** o cliente tenta enviar outro país e um `X-Forwarded-For` falso, mas a loja usa o IP da conexão e ignora a localização enviada.
- **A. Replay:** o gateway recusa o reenvio da mensagem legítima já processada (`INVALID_NONCE`).
- **B. Adulteração:** um byte da mensagem cifrada é alterado (modelo de tentativa de modificar o valor da transação), e o AES-GCM detecta a modificação (`INVALID_AUTHENTICATION`).

O script usa o envelope de pagamento **já armazenado para fins de demonstração** no banco local da loja. Não precisa conhecer a chave para reenviar ou adulterar bytes da mensagem; a frase compartilhada é utilizada pelo demonstrador apenas para decifrar a resposta do gateway.

## 5. IP2Location: baixar e configurar o banco oficial

A aplicação implementa a consulta local ao **IP2Location**, conforme o enunciado. O arquivo BIN não acompanha o projeto e deve ser baixado pelo grupo diretamente da fonte oficial:

1. Acesse **https://lite.ip2location.com/** e crie uma conta gratuita, se necessário.
2. Baixe a base **IP2Location LITE DB11 (BIN)**, com país, região, cidade, latitude e longitude aproximadas. ASN/organização são exibidos quando presentes no banco utilizado.
3. Extraia o arquivo e coloque-o no caminho `data/ip2location/IP2LOCATION-LITE-DB11.BIN` (renomeie o arquivo BIN extraído, se necessário).
4. Execute uma consulta real a um IP público com:

```powershell
python -m scripts.geo_demo
```

Informe, por exemplo, `8.8.8.8`. O retorno real dependerá da versão do banco e da precisão aproximada do serviço.

### Geolocalização durante login e pagamento

- O **servidor da loja** consulta o IP observado na conexão, nunca um IP indicado pelo cliente em um campo JSON ou cabeçalho não confiável.
- Na autenticação, registra o país do acesso. Se mudar em um login futuro, bloqueia a autenticação como alteração relevante de contexto.
- Na compra, envia ao gateway o IP, as informações geográficas e a prova de autenticação, protegidos por AES-GCM.
- O **gateway** consulta novamente o IP recebido do servidor de confiança e compara as informações de país/região/cidade. Um IP público sem banco disponível é recusado.

**Limitação do localhost:** `127.0.0.1` é um IP de loopback, não possui localização geográfica real. Nesse caso, o sistema registra explicitamente `source: LOOPBACK` e `country: LOCAL` para a demonstração local. **Isso não é um resultado do IP2Location**. A consulta pública real pode ser demonstrada com `scripts.geo_demo`. Para fazer o IP2Location participar do login com um IP público realmente observado, é necessário executar a loja em um ambiente de rede apropriado e protegido por TLS; o exemplo é intencionalmente restrito ao localhost.

## 6. Estrutura dos arquivos

```text
loja-segura/
  client/              Cliente CLI, menus e chamadas HTTP
  store/               Cadastro, login, TOTP, catálogo, carrinho e checkout
  gateway/             Validação independente e controle de nonces
  shared/              Criptografia AEAD, consulta IP2Location e catálogo oficial
  scripts/             Demonstrações de ataques e consulta de IP público
  tests/               Testes automatizados
  data/                Bancos SQLite (gerados na execução) e IP2Location BIN (externo)
  docs/CODIGO.md       Documentação dos módulos, protocolo e decisões de segurança
  requirements.txt     Dependências
```

### Documentação HTTP automática

- Loja: http://127.0.0.1:8000/docs
- Gateway: http://127.0.0.1:8001/docs

## 7. Armazenamento e reinicialização

O programa cria `data/store.db` e `data/gateway.db` automaticamente. Esses arquivos **não são incluídos no ZIP**, nem devem ser enviados ao Git. A loja guarda usuários, produtos, sessões, carrinho, pedidos e envelopes cifrados. O gateway guarda transações e nonces utilizados.

Na reinicialização, use a **mesma frase-mestra** com o mesmo `store.db`. Sem ela, não é possível recuperar os segredos TOTP cifrados. A frase loja–gateway deve ser igual nos dois serviços enquanto estiverem ligados.

Para reiniciar completamente o laboratório, encerre os três programas e apague os arquivos `.db` em `data/`. Isso apagará os usuários, carrinhos, pedidos e histórico de nonces.

**Não use cartões ou dados bancários reais**. Este projeto demonstra mecanismos de segurança em um sistema acadêmico simplificado, não um sistema comercial auditado.
