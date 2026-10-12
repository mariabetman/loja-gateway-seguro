# Relatório técnico — Loja Segura

## Arquitetura

Cliente de terminal (Python/HTTPX) -> API da loja (FastAPI) -> futura API de gateway independente. Nesta primeira etapa, apenas o cadastro foi implementado.

## Cadastro

A loja persiste nome, e-mail normalizado, hash de senha Argon2id e segredo TOTP cifrado com AES-GCM. O segredo TOTP é gerado de maneira aleatória e retornado uma única vez para a configuração do autenticador. A cifra do segredo é derivada de frase-mestra do operador por Scrypt com salt aleatório por registro. O banco SQLite não armazena senha nem segredo TOTP em claro.

## Demais seções

A completar ao implementar autenticação, geolocalização, loja, gateway, protocolo de comunicação, defesa contra replay e ataques.
