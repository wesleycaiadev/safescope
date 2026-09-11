# ADR 0001 — SQLite antes de PostgreSQL

**Status:** aceito.

O MVP usa SQLite local, preferencialmente com WAL, para remover custo e operação inicial. Regras de domínio não dependem do banco e migrations serão versionadas. PostgreSQL/Supabase entra quando houver necessidade real de múltiplos usuários, RLS e serviço hospedado.
