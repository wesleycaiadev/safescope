# ADR 0006 — Esquema fixo por migration

Cada revisão Alembic declara suas próprias tabelas e índices, sem importar os modelos atuais para criar o banco. A revisão inicial criava antecipadamente tabelas adicionadas depois, causando `DuplicateTable` ao executar a revisão de membros no Neon.

A revisão inicial agora contém apenas as onze tabelas originais. A revisão seguinte continua responsável por `organization_memberships`, seu índice e a restrição de papéis. A correção não remove tabelas nem dados em bancos existentes. Testes executam as migrations reais, preservam registros entre revisões e verificam a geração de SQL PostgreSQL.
