# Brief de implementação

Implemente o SafeScope incrementalmente como uma plataforma defensiva de auditoria web. Preserve o domínio puro em `safescope_core`. Nenhum scanner escolhe modo ou autorização: a execução deve chamar `ScanPolicyEngine` e cada requisição deve passar pelo `RequestGate` e `SSRFGuard`.

Comece pela conclusão da Fase 1: persistência SQLite com migrations reversíveis, modelos de Target/Scope/Authorization, verificação DNS TXT ou arquivo `/.well-known/safescope-verification.txt` com token aleatório de uso único e um transporte `httpx` protegido que resolva DNS e revalide redirecionamentos. Mantenha apenas scanners passivos. Escreva testes para políticas, SSRF, redirecionamentos e verificação. Não crie interface, scanner ativo ou integração externa antes dos critérios de aceite da fase estarem verdes.
