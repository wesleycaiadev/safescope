# Roadmap de implementação

**Status:** 4 de 5 fases concluídas. Resta 1 fase: produção.

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

## Fase 5 — produção (em andamento)

- [x] Adaptador PostgreSQL (`asyncpg`), autenticação Supabase opt-in, papéis por organização e isolamento no backend.
- [x] Migration Supabase com RLS, nenhum acesso direto de escrita e auditoria append-only.
- [ ] Provisionar um projeto Supabase e aplicar migrations/RLS em ambiente de produção.
- [ ] Integração autenticada e testes ativos somente após revisão de controles, testes de segurança e ROE válida.

Critério de avanço: `make check` verde, revisão de segurança e documentação atualizada. As Fases 1 a 4 estão concluídas; a Fase 5 depende do provisionamento controlado do ambiente de produção.
