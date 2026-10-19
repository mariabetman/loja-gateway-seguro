# Loja Virtual Segura — INE5680

Projeto Python com três programas: **cliente de terminal**, **API da loja** e **gateway de pagamento independente**. A loja e o gateway usam bancos SQLite separados. Nenhum pagamento real é processado.

## 1. Requisitos e instalação

- Python **3.11 ou superior**.
- Aplicativo compatível com TOTP (Google Authenticator, Microsoft Authenticator etc.).
- Internet para o túnel HTTPS e a base **IP2Location LITE DB11 (BIN)** para consulta local (seção 5).
- Executável `cloudflared` para criar o túnel.

No Windows x64, coloque os arquivos abaixo nos caminhos indicados.

| Arquivo | Caminho no projeto |
| --- | --- |
| Executável `cloudflared` | `.tools/cloudflared.exe` |
| Base IP2Location DB11 | `data/ip2location/IP2LOCATION-LITE-DB11.BIN` |

Em Linux/macOS, instale o `cloudflared` correspondente ao sistema e deixe-o no PATH.

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

## 2. Executar a aplicação

Na raiz do projeto, com o ambiente virtual ativado:

```powershell
python main.py
```

Informe a **frase-mestra da loja** e a **frase compartilhada loja–gateway**, ambas com no mínimo 16 caracteres. Na primeira execução, escolha as frases; ao reutilizar o banco, mantenha a mesma frase-mestra (seção 7).

O iniciador abre loja e gateway em processos separados, cria o túnel HTTPS e apresenta o menu do cliente já configurado com a URL pública. O cliente usa IPv4 e verifica o certificado HTTPS. As frases são entregues aos serviços por pipes locais, sem serem salvas em texto legível.

Ao sair do menu ou pressionar Ctrl+C, o programa encerra os serviços e o túnel. Para executar o laboratório sem Internet e com contexto `LOCAL`, use:

```powershell
python main.py --local
```

Se a inicialização falhar, confira os arquivos da seção 1 e se as portas 8000/8001 estão livres. Para falhas do túnel, verifique a conexão, o firewall e eventual configuração anterior em `.cloudflared`.

### Fluxo de uso

1. Escolha **1 — Cadastro** e informe nome, e-mail e senha (mínimo 12 caracteres).
2. Escaneie o QR Code exibido pelo terminal ou cadastre manualmente o segredo TOTP no aplicativo autenticador. O segredo aparece somente nessa operação.
3. Escolha **2 — Login**; informe e-mail e senha e depois o código de **6 dígitos** mostrado no celular.
4. Escolha **4 — Produtos** para consultar o catálogo e **6 — Alterar carrinho** para escolher um produto (`P01`, `P02` ou `P03`) e uma quantidade.
5. Escolha **5 — Carrinho** para visualizar os valores e **7 — Comprar** para enviar a operação cifrada ao gateway.
6. Veja a aprovação ou o bloqueio. Se a resposta do gateway se perder ou for inválida, o pedido fica como `ERROR`, indicando resultado não confirmado, e o carrinho é preservado. A opção **8 — Pedidos** mostra o histórico; **9 — Localização** exibe o contexto IP observado pelo servidor.
7. **10 — Logout** encerra a sessão; **0 — Sair** fecha a aplicação e seus serviços.

O cliente nunca define o preço final nem a localização; a loja obtém preços do seu catálogo e geolocalização a partir do IP da conexão.

**IMPORTANTE:** no modo `--local`, o tráfego cliente–loja usa HTTP em localhost. Na execução padrão, o cliente acessa a loja por HTTPS e o gateway continua local. **Não use senhas reais** no laboratório.

## 3. Testes automatizados

```powershell
python -m pytest -q
```

Encerre a aplicação antes dos testes: os testes do iniciador usam as portas 8000 e 8001. A suíte cobre inicialização e encerramento dos serviços, validação do IP encaminhado, cadastro, senha, TOTP, sessão, carrinho, pagamento, adulteração, replay e timestamp. Os testes do adaptador IP2Location usam dados simulados; a consulta real é descrita na seção 5.

## 4. Demonstração dos ataques exigidos

Com `python main.py` executando e um usuário já cadastrado, abra **outro terminal na mesma máquina**, ative o ambiente virtual e configure a URL exibida pelo iniciador:

```powershell
$env:STORE_URL = 'https://URL-EXIBIDA.trycloudflare.com'
python -m scripts.demo_attacks
```

Substitua pela URL real. Se estiver executando com `--local`, use `http://127.0.0.1:8000`.

O programa solicita o e-mail, a senha do usuário, a frase compartilhada loja–gateway (somente para decifrar e **inspecionar a resposta durante a demonstração**) e um código TOTP válido. Se acabou de fazer login, aguarde o aplicativo autenticador mostrar um código novo: o sistema impede reutilizar o código já aceito. Ele realiza uma compra de teste e mostra:

- **C. TOTP inválido:** o servidor recusa a tentativa com código incorreto.
- **D. Localização falsa:** o cliente envia localização e `X-Forwarded-For` falsos; o script verifica se a compra mantém o contexto real consultado na loja e o total calculado pelo servidor.
- **A. Replay:** o gateway recusa o reenvio da mensagem legítima já processada (`INVALID_NONCE`).
- **B. Alteração do valor:** usando o formato e os dados conhecidos do pedido, o script modifica o trecho cifrado de `amount` para tentar trocar R$ 100,00 por R$ 1.000,00. Sem recalcular a tag, o AES-GCM rejeita a mensagem (`INVALID_AUTHENTICATION`).

O script prepara um carrinho de duas unidades de P01 (R$ 100,00), substituindo os itens anteriores, e usa o envelope de pagamento **já armazenado para fins de demonstração** no banco local da loja. A alteração do valor pressupõe conhecimento do formato e dos dados do pedido, sem usar a chave nem decifrar o envelope. A frase compartilhada é utilizada pelo demonstrador apenas para decifrar a resposta do gateway.

## 5. IP2Location: baixar e configurar o banco oficial

A aplicação consulta o **IP2Location** localmente. Para obter ou atualizar a DB11:

1. Acesse **https://lite.ip2location.com/** e crie uma conta gratuita, se necessário.
2. Baixe a base **IP2Location LITE DB11 (BIN)**, com país, região, cidade, latitude e longitude aproximadas. ASN/organização são exibidos quando presentes no banco utilizado.
3. Extraia o arquivo e coloque-o no caminho `data/ip2location/IP2LOCATION-LITE-DB11.BIN` (renomeie o arquivo BIN extraído, se necessário).
4. Execute uma consulta real a um IP público com:

```powershell
python -m scripts.geo_demo
```

Informe, por exemplo, `8.8.8.8`. O retorno real dependerá da versão do banco e da precisão aproximada do serviço.

### Geolocalização durante login e pagamento

- A **loja** usa o IP encaminhado pelo túnel somente após validar a origem local, o Host configurado e os cabeçalhos de contexto. No modo local, usa o IP da conexão. Nunca aceita como verdade o IP informado no JSON ou em `X-Forwarded-For`.
- Na autenticação, registra o país do acesso. Se mudar em um login futuro, bloqueia a autenticação como alteração relevante de contexto.
- Na compra, envia ao gateway o IP, as informações geográficas e a prova de autenticação, protegidos por AES-GCM.
- O **gateway** consulta novamente o IP recebido do servidor de confiança e compara as informações de país/região/cidade. Um IP público sem banco disponível é recusado.

**Limitação do localhost:** com `--local`, o sistema registra `source: LOOPBACK` e `country: LOCAL`; isso não é um resultado do IP2Location. Ao alternar entre esse modo e o túnel, use um novo usuário de demonstração, pois a política de mudança de país também se aplica à troca de `LOCAL` para um país real.

## 6. Estrutura dos arquivos

```text
loja-gateway-seguro/
  main.py              Inicia serviços, túnel e cliente; encerra tudo ao sair
  .tools/              Executável cloudflared (adicionado separadamente)
  client/              Cliente CLI, menus e chamadas HTTP
  store/               Cadastro, login, TOTP, catálogo, carrinho e checkout
  gateway/             Validação independente e controle de nonces
  shared/              Criptografia AEAD, consulta IP2Location e catálogo oficial
  scripts/             Demonstrações de ataques e consulta de IP público
  tests/               Testes automatizados
  data/                Bancos SQLite (gerados na execução) e IP2Location BIN (externo)
  docs/CODIGO.md       Arquitetura, protocolo, segurança e limitações
  requirements.txt     Dependências
```

### Documentação HTTP automática

- Loja: URL HTTPS exibida pelo iniciador seguida de `/docs`; com `--local`, http://127.0.0.1:8000/docs.
- Gateway: http://127.0.0.1:8001/docs

## 7. Armazenamento e reinicialização

O programa cria `data/store.db` e `data/gateway.db` automaticamente. Esses arquivos **não são incluídos no ZIP**, nem devem ser enviados ao Git. A loja guarda usuários, produtos, sessões, carrinho, pedidos e envelopes cifrados. O gateway guarda transações e nonces utilizados.

Na reinicialização, use a **mesma frase-mestra** com o mesmo `store.db`: ela permite recuperar os segredos TOTP cifrados. A frase loja–gateway pode mudar entre execuções; o iniciador entrega o mesmo valor aos dois serviços. Decifrar envelopes antigos exige a frase usada naquela execução.

Para reiniciar completamente o laboratório, saia da aplicação e apague os arquivos `.db` em `data/`. Isso apagará os usuários, carrinhos, pedidos e histórico de nonces. Preserve a DB11 na subpasta `ip2location`.

**Não use cartões ou dados bancários reais**. Este projeto demonstra mecanismos de segurança em um sistema acadêmico simplificado, não um sistema comercial auditado.
