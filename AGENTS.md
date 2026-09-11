# Regras do repositório SafeScope

1. `safescope_core` é domínio puro: não importa FastAPI, SQLAlchemy ou bibliotecas de rede.
2. Apenas o `ScanPolicyEngine` e o `RequestGate` autorizam scanners e requisições. A UI e a CLI nunca decidem permissões.
3. Todo scanner é um plugin com metadados de risco e recebe um transporte já protegido.
4. Todo achado tem evidência sanitizada; segredos, cookies e dados pessoais não entram em logs ou relatórios.
5. Escritas no alvo exigem autorização vigente, caminho permitido e `ResourceLedger`; recursos de prova devem ser limpos.
6. Não implementar capacidades para acesso não autorizado, exfiltração, persistência, evasão ou destruição.
7. APIs públicas têm type hints. Rode `make check` antes de considerar uma fase concluída.
8. Toda alteração de arquitetura ou de postura de segurança deve atualizar um ADR em `docs/adr`.
