# Modo AGGRESSIVE: controles implementados

A fundação segura está implementada, mas os scanners ativos permanecem fora da
fila pública. Antes de qualquer uso fora do laboratório, estes controles são
obrigatórios:

- ROE assinada e vinculada ao alvo; verificação de domínio não substitui a ROE.
- Janela de execução, origens incluídas, exclusões, verbos, volume e taxa gravados no snapshot do scan.
- Contas de teste fornecidas pelo cliente; jamais senha real de administrador.
- Kill switch consultado antes de cada requisição e processos externos encerrados de forma controlada.
- Orçamento de requisições e limite por host.
- Evidência com mascaramento, hash e retenção definida; sem dumps de dados.
- Recursos de prova registrados no `ResourceLedger`, com limpeza confirmada.
- Audit log append-only de autorização, execução e interrupção.

Os scanners IDOR e matriz de autorização aceitam somente objetos-canário
declarados e precisam de duas identidades de teste do alvo. O ZAP Baseline
continua sendo a única integração externa disponível no dashboard e permanece
passivo. Novas famílias ativas exigem ADR, gabarito positivo/negativo e revisão
dos controles antes de entrar no registro.
