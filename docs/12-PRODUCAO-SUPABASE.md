# Produção: PostgreSQL, Supabase e isolamento de tenants

## O que a Fase 5 entrega

O SafeScope aceita `postgresql://...` e usa `asyncpg` automaticamente. Com `SAFESCOPE_MODE=production`, toda rota de dados exige um Bearer token válido e o backend o confere no endpoint oficial do Supabase Auth. No modo `development`, o ator local existe somente para preservar o fluxo SQLite de desenvolvimento.

Cada organização tem membros com os papéis `VIEWER`, `MEMBER`, `ADMIN` e `OWNER`. A API filtra leituras e valida cada mutação pelo vínculo de organização, sem confiar em dados mutáveis do perfil do usuário.

## Provisionamento

1. Crie um projeto Supabase e habilite o provedor de login desejado.
2. Copie `.env.example` para o ambiente do backend. Defina `DATABASE_URL` com a connection string PostgreSQL, `SAFESCOPE_MODE=production`, `SUPABASE_URL` e `SUPABASE_PUBLISHABLE_KEY`.
3. No ambiente do dashboard, defina somente `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` e `NEXT_PUBLIC_SAFESCOPE_API`. Chaves `service_role` e secretas ficam exclusivamente fora do frontend.
4. Execute `./.venv/bin/alembic -x db_url="$DATABASE_URL" upgrade head` para criar o esquema de aplicação.
5. Execute `npx supabase link --project-ref SEU_PROJECT_REF` e depois `npx supabase db push` para aplicar `supabase/migrations/`. A migration habilita RLS, remove escrita direta para `anon`/`authenticated` e instala o trigger append-only de `audit_logs`.
6. Faça login no dashboard e crie a primeira organização. O criador vira `OWNER`; adicione outros usuários pelo endpoint de membros usando o UUID da conta Supabase.

## Limites de segurança

- O painel manda o access token no header `Authorization`; downloads de relatório usam `fetch`, portanto não burlam autenticação.
- O backend verifica o token junto ao Supabase Auth. Uma indisponibilidade do Auth retorna `503`; token ausente, expirado ou inválido retorna `401`.
- RLS usa funções privadas de busca de tenant com `auth.uid()` e não usa `user_metadata` como autorização. Tabelas expostas só concedem `SELECT` ao papel `authenticated`; toda escrita continua no backend.
- `audit_logs` não aceita `UPDATE` ou `DELETE` no banco. Eventos importantes do controle de organizações, escopo, autorização, fila e correção são incluídos nessa trilha.

Antes de liberar um domínio público, use o SQL Editor/Advisors do Supabase para inspecionar as políticas e execute testes de negação entre duas contas de organizações diferentes.
