# ADR-0008 — Fundação ativa restrita a canários e laboratório

## Decisão

A primeira capacidade ativa do SafeScope é limitada a IDOR e matriz de
autorização sobre objetos-canário explicitamente declarados. Ela não é registrada
na fila passiva nem exposta como botão no dashboard.

As sessões autenticadas usam canais separados por identidade e segredos
efêmeros. Um achado exige controle negativo estável. Mutações devem registrar a
restauração em journal atômico antes da escrita, e o worker tenta recuperar
ações pendentes antes de aceitar outro job.

## Motivo

Testar autorização com IDs coletados de usuários reais cria risco de acesso a
dados e falso positivo. Canários e duas contas de teste permitem provar a falha
sem enumerar recursos de terceiros. Manter o registro ativo fora da fila pública
evita que uma configuração incompleta transforme um scan passivo em ativo.

## Consequências

- O painel permanece de usuário único e com scans públicos passivos.
- Duas identidades pertencem ao alvo auditado, não à plataforma SafeScope.
- Novas famílias de scanner não são consequência automática desta decisão.
- Cada extensão exige ROE, allowlist de payload, oráculo, journal quando houver
  escrita e testes de gabarito positivos e negativos.
