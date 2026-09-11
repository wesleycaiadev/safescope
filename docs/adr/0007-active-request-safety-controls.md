# ADR-0007 — Controles prévios para requisições ativas

## Decisão

O `RequestGate` revalida a janela da autorização antes de cada requisição,
recusa tipos de conteúdo fora da allowlist e exige um identificador aprovado
para toda requisição marcada como probe. O transporte preserva essa marca e o
identificador ao reavaliar redirecionamentos.

`DELETE` só é permitido em recurso registrado no `ResourceLedger` como criado
pelo próprio scan. Um snapshot autoriza restauração após `PUT` ou `PATCH`, mas
não autoriza remover um recurso preexistente.

## Motivo

Uma autorização pode expirar durante um job. Além disso, limitar apenas verbo
e URL não limita o formato nem a família de teste enviada. Os controles precisam
falhar fechados na fronteira imediatamente anterior à rede, independentemente
da API, da interface ou do scanner que originou a requisição.

## Consequências

- Scanners ativos futuros devem marcar probes com `is_probe=True` e usar um
  `payload_id` presente no snapshot da ROE.
- Tipos de conteúdo precisam ser explicitamente autorizados antes do envio.
- Redirecionamentos mantêm a classificação do probe e passam novamente pelo gate.
- Esta decisão implementa somente a barreira de segurança; não adiciona payloads
  de exploração nem habilita o modo ativo na interface.
