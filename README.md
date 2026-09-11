# SafeScope

Plataforma local-first para auditoria de segurança web, gestão de autorização e relatórios de remediação.

O produto opera por política aplicada no backend: uma avaliação `PASSIVE` usa apenas navegação normal; qualquer ação além disso exige alvo verificado, autorização vigente e escopo explícito. O SafeScope não deve ser usado para acessar sistemas sem autorização.

## Estado atual

As Fases 1 a 5 estão implementadas. O produto possui banco SQLite ou PostgreSQL Neon, API FastAPI, dashboard Next.js, fila e worker contínuo, scanners passivos, evidências sanitizadas, Security Score, relatórios e acompanhamento de correção. A Fase 6 prepara, sem habilitar por padrão, os controles necessários para futuros testes autenticados e ativos em laboratório autorizado.

## Desenvolvimento local

Requer Python 3.12 ou superior.

```bash
make bootstrap
make check
```

Para executar o produto, use três terminais a partir da raiz do repositório:

```bash
# Terminal 1 — API e documentação em http://127.0.0.1:8000/docs
make dev-api

# Terminal 2 — dashboard em http://localhost:3000
make dev-web

# Terminal 3 — processa continuamente a fila local
make worker
```

Também é possível processar somente um job ou consultar a fila:

```bash
./.venv/bin/safescope worker once
./.venv/bin/safescope worker status
```

O dashboard cria organizações, projetos, targets, regras de escopo e registros de autorização. Ele dispara somente avaliações `PASSIVE`; autorizações cadastradas nesta fase não habilitam testes ativos nem mutações.

## Relatórios e ZAP Baseline

O dashboard gera relatórios executivo e técnico em PDF, além de templates de proposta e ROE para o target selecionado. Os PDFs contêm somente findings e evidências já sanitizadas.

O ZAP Baseline é opcional e vem desativado. A integração detecta o lançador oficial `zap-baseline.py` no `PATH` ou a imagem oficial `ghcr.io/zaproxy/zaproxy:stable` pelo Docker. Marque a opção correspondente antes de enfileirar o scan. Ela usa argumentos fixos e só executa quando o snapshot do job permite explicitamente o scanner passivo. Consulte [`docs/11-RELATORIOS-E-ZAP.md`](docs/11-RELATORIOS-E-ZAP.md) para os limites e endpoints.

## PostgreSQL Neon e autenticação opcional

O modo local pode usar SQLite ou uma URL PostgreSQL do Neon em `DATABASE_URL`.
No cenário atual de usuário único, mantenha `SAFESCOPE_MODE=development` e não
publique a API na internet. O banco não substitui autenticação: antes de expor o
sistema publicamente, configure um provedor de identidade e mude para o modo de
produção.

Em um banco PostgreSQL vazio, aplique o esquema do SafeScope:

```bash
./.venv/bin/alembic upgrade head
```

O adaptador opcional de autenticação Supabase e suas regras RLS permanecem no
repositório para uma futura implantação multiusuário. Eles não devem ser
aplicados ao Neon, pois dependem do schema `auth` do Supabase. Veja
[`docs/12-PRODUCAO-SUPABASE.md`](docs/12-PRODUCAO-SUPABASE.md).

## Modos

| Modo | Autorização | Limite |
| --- | --- | --- |
| `PASSIVE` | Não | GET/HEAD e observação pública normal |
| `GUIDED` | Alvo verificado + autorização | testes leves previstos no escopo |
| `AGGRESSIVE` | ROE assinada, escopo e janela válidos | somente procedimentos aprovados, com limites e limpeza |

## Documentação

Comece por `docs/00-VISAO.md`, `docs/01-ARQUITETURA.md` e `docs/03-MODOS-E-POLITICA.md`.
