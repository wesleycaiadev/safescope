# ADR 0004 — Ledger para operações de escrita

**Status:** aceito.

Qualquer recurso de prova criado durante teste futuro deverá ser registrado no `ResourceLedger` e limpo. Escritas em recursos preexistentes exigem caminho explicitamente permitido e snapshot para restauração. Isso não autoriza dano: é uma barreira adicional dentro de uma ROE válida.
