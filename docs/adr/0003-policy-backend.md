# ADR 0003 — Política no backend

**Status:** aceito.

Permissões não vivem na UI, CLI ou configuração do scanner. `ScanPolicyEngine` decide se o plugin pode iniciar; `RequestGate` decide se cada requisição pode ocorrer. A decisão é auditável, e o transporte não conecta antes de validar esquema, IP e escopo.
