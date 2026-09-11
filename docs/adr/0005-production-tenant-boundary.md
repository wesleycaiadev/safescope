# ADR 0005 — Produção com Supabase Auth e isolamento por organização

**Status:** aceito.

O modo de desenvolvimento continua com SQLite e um ator local explícito. Em produção, o backend exige um token Bearer e consulta o endpoint de usuário do Supabase Auth; nenhuma chave administrativa é enviada ao navegador.

Associações `organization_memberships` formam o limite de tenant. A API aplica papéis em cada leitura e mutação, enquanto a migration Supabase habilita RLS em todas as tabelas `public`, concede somente leitura ao papel autenticado e torna `audit_logs` imutável por trigger. O RLS não usa `user_metadata`; deriva a identidade com `auth.uid()`.
