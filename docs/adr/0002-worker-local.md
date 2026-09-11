# ADR 0002 — Worker local no MVP

**Status:** aceito.

Scans executam na máquina controlada pelo analista, não em infraestrutura pública. Isso reduz custo, simplifica segregação de dados e evita expor um motor de segurança na internet. API e dashboard só poderão enviar jobs dentro da política; o worker continuará a validar o snapshot localmente.
