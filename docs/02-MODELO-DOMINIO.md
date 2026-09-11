# Modelo de domínio

| Entidade | Responsabilidade |
| --- | --- |
| Organization / Member | Isolamento de clientes e papéis |
| Project | Contexto comercial de uma avaliação |
| Target | URL-base, domínio, estado de verificação e modo máximo |
| Scope | Origens incluídas, exclusões, métodos e limites |
| Authorization | ROE, representante, janela, permissões e aceite |
| ScanJob / ScanRun | Pedido e execução imutável de uma avaliação |
| Evidence | Prova sanitizada, hash, fonte e data |
| Finding | Risco, confiança, impacto, correção e estado |
| Report | Versão executiva ou técnica, vinculada a findings |
| AuditLog | Registro append-only de ações importantes |

Um `Finding` não pode existir sem ao menos uma `Evidence`. Credenciais de teste não pertencem a esse modelo persistente: são temporárias no worker.

Estados de finding: `OPEN`, `CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `IN_PROGRESS`, `FIXED`, `RETEST_REQUIRED` e `CLOSED`.
