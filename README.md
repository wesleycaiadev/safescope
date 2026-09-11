# SafeScope

Plataforma local-first para auditoria de segurança web, gestão de autorização e relatórios de remediação.

O produto opera por política aplicada no backend: uma avaliação `PASSIVE` usa apenas navegação normal; qualquer ação além disso exige alvo verificado, autorização vigente e escopo explícito. O SafeScope não deve ser usado para acessar sistemas sem autorização.

## Estado atual

As Fases 1, 2 e 3 estão implementadas. O MVP local possui banco SQLite, API FastAPI, dashboard Next.js, fila e worker contínuo, scanners passivos, evidências sanitizadas, Security Score e acompanhamento de correção. Relatórios/exportação são a próxima fase; autenticação e infraestrutura de produção permanecem na Fase 5.

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

## Produção com PostgreSQL e Supabase

O modo local permanece em SQLite. Para produção, use uma URL PostgreSQL, configure `SAFESCOPE_MODE=production`, `SUPABASE_URL` e `SUPABASE_PUBLISHABLE_KEY` no backend; no dashboard, configure apenas as variáveis `NEXT_PUBLIC_*` correspondentes. Nunca exponha uma `service_role` ou chave secreta no navegador.

Em um ambiente PostgreSQL vazio, aplique primeiro o esquema do SafeScope e depois as regras específicas do Supabase:

```bash
./.venv/bin/alembic -x db_url="$DATABASE_URL" upgrade head
npx supabase link --project-ref SEU_PROJECT_REF
npx supabase db push
```

A primeira organização criada por uma sessão autenticada recebe o papel `OWNER`. Esse owner pode registrar membros usando `POST /organizations/{organization_id}/members` com o UUID do usuário Supabase. As políticas RLS permitem somente leitura de dados da própria organização; escritas são mediadas pela API autenticada. Veja [`docs/12-PRODUCAO-SUPABASE.md`](docs/12-PRODUCAO-SUPABASE.md).

## Modos

| Modo | Autorização | Limite |
| --- | --- | --- |
| `PASSIVE` | Não | GET/HEAD e observação pública normal |
| `GUIDED` | Alvo verificado + autorização | testes leves previstos no escopo |
| `AGGRESSIVE` | ROE assinada, escopo e janela válidos | somente procedimentos aprovados, com limites e limpeza |

## Documentação

Comece por `docs/00-VISAO.md`, `docs/01-ARQUITETURA.md` e `docs/03-MODOS-E-POLITICA.md`.
