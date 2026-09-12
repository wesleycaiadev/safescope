# Roadmap de implementação

**Status:** 6 de 6 fases concluídas. Não resta fase de implementação no roadmap
atual; novas famílias de scanner devem entrar como extensões revisadas.

## Fase 1 — fundação segura

- [x] Estrutura de pacotes e testes.
- [x] Política, gate, SSRF guard, ledger, kill switch e cofre efêmero.
- [x] Scanners passivos de TLS e headers.
- [x] Documentação base e política de escopo.
- [x] Modelos persistentes, SQLite, Alembic e challenges de domínio por arquivo/DNS.
- [x] Transporte HTTP protegido que conecta scanners ao `RequestGate`.

## Fase 2 — cobertura passiva

- [x] Cookies, CSP, CORS, DNS, tecnologias, JavaScript, arquivos expostos e `security.txt`.
- [x] Normalização, deduplicação, evidência sanitizada e Security Score.

## Fase 3 — produto mínimo

- [x] API FastAPI com CRUD de organizações, projetos, alvos, escopos e autorizações.
- [x] Fila de jobs no SQLite e worker/CLI local, com execução contínua, status, falha controlada e auditoria.
- [x] Dashboard de targets, scans, findings, evidências, Security Score e progresso de correção.

## Fase 4 — entregáveis

- [x] Relatório executivo e técnico, exportação PDF e templates de proposta/ROE.
- [x] ZAP Baseline passivo, sempre via allowlist e política. (imagem oficial validada localmente via Docker)

## Fase 5 — persistência de produção

- [x] Adaptador PostgreSQL (`asyncpg`), autenticação Supabase opt-in, papéis por organização e isolamento no backend.
- [x] Migration Supabase com RLS, nenhum acesso direto de escrita e auditoria append-only.
- [x] PostgreSQL Neon provisionado e migrations Alembic aplicadas em banco vazio.
- [x] Operação local de usuário único mantida em modo de desenvolvimento; autenticação pública continua desabilitada.

## Fase 6 — base segura para testes autenticados

- [x] Modos reais e teto de risco por modo; `GUIDED` e `AGGRESSIVE` não são aliases passivos.
- [x] Gate por requisição com escopo, exclusões, verbo, tipo de conteúdo, payload aprovado, janela vigente, orçamento, kill switch e reavaliação de redirect. `DELETE` somente em recurso criado pelo scan.
- [x] Transporte HTTP com conexão presa ao IP validado, SNI/domínio original, redirect reavaliado e pool limitado pelo `max_concurrency` da ROE.
- [x] `LoginProfile` e `SessionRuntime` para contas do alvo, usando o cofre efêmero e verificando a saúde da sessão antes de cada scanner autenticado.
- [x] Descoberta autorizada por OpenAPI, schema GraphQL fornecido e referências JavaScript, sempre filtrada pelas origens do escopo.
- [x] Oráculos diferencial e de autorização com controle negativo e evidência comparativa sanitizada.
- [x] Journal persistente de mutações, registro antes da escrita, restauração e replay de recuperação no boot do worker.
- [x] Scanners ativos de matriz de autorização/IDOR somente sobre canários declarados, com jitter adaptativo e planos de concorrência limitados pela ROE.
- [x] Laboratório vulnerável isolado com gabarito positivo e negativo, validado em testes e em imagem Docker local.

Critério concluído: `make check` verde, controles documentados e scanners ativos
fora da fila pública. Uma ROE válida, alvo verificado, contas-canário e allowlists
continuam obrigatórios antes de qualquer uso fora do laboratório.
