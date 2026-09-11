# Modo AGGRESSIVE: requisitos futuros

Esta fase não está implementada. Antes de qualquer scanner ativo, os seguintes controles são obrigatórios:

- ROE assinada e vinculada ao alvo; verificação de domínio não substitui a ROE.
- Janela de execução, origens incluídas, exclusões, verbos, volume e taxa gravados no snapshot do scan.
- Contas de teste fornecidas pelo cliente; jamais senha real de administrador.
- Kill switch consultado antes de cada requisição e processos externos encerrados de forma controlada.
- Orçamento de requisições e limite por host.
- Evidência com mascaramento, hash e retenção definida; sem dumps de dados.
- Recursos de prova registrados no `ResourceLedger`, com limpeza confirmada.
- Audit log append-only de autorização, execução e interrupção.

O primeiro marco de integração externa é apenas ZAP Baseline em modo passivo. Ferramentas de teste ativo não devem ser acopladas ao MVP até que todos esses requisitos sejam verificáveis por testes.
