# Roadmap de implementação

**Status:** 5 fases concluídas. A Fase 6, base segura para testes autenticados,
está em andamento com 3 de 9 passos concluídos.

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

## Fase 6 — base segura para testes autenticados (em andamento)

- [x] Modos reais e teto de risco por modo; `GUIDED` e `AGGRESSIVE` não são aliases passivos.
- [x] Gate por requisição com escopo, exclusões, verbo, tipo de conteúdo, payload aprovado, janela vigente, orçamento, kill switch e reavaliação de redirect. `DELETE` somente em recurso criado pelo scan.
- [x] Transporte HTTP com conexão presa ao IP validado, SNI/domínio original, redirect reavaliado e pool limitado pelo `max_concurrency` da ROE.
- [ ] `LoginProfile` e `SessionRuntime`, usando o cofre efêmero e verificando a saúde da sessão antes de cada scanner autenticado.
- [ ] Descoberta autorizada de superfície por especificações fornecidas pelo cliente e artefatos públicos dentro do escopo.
- [ ] Oráculos com controle negativo e evidência comparativa sanitizada.
- [ ] Journal persistente de mutações, restauração e replay de recuperação no boot do worker.
- [ ] Scanners ativos controlados, começando por matriz de autorização/IDOR em laboratório, com jitter adaptativo e planos de concorrência explícitos, sem habilitação automática em produção.
- [ ] Laboratório vulnerável isolado no CI, com gabarito e métricas de falso positivo/negativo.

Critério de avanço: `make check` verde, revisão de segurança, ROE válida e
testes no laboratório isolado antes de qualquer habilitação de scan ativo.
