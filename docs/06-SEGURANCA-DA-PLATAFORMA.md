# Segurança da plataforma

## Isolamento e acesso

Os papéis planejados são `PLATFORM_OWNER`, `SECURITY_ANALYST`, `CLIENT_ADMIN` e `CLIENT_VIEWER`. Cada entidade persistente terá `organization_id`; ao migrar para Supabase/PostgreSQL, Row Level Security deverá impedir leitura cruzada entre organizações. Princípio de menor privilégio é obrigatório.

## Proteções de rede

URLs informadas por usuários são hostis por padrão. O transporte permitirá somente `http` e `https`, resolverá DNS a cada conexão e bloqueará loopback, redes privadas, link-local, multicast, endereços não especificados/reservados e metadata endpoints. Redirecionamentos serão reavaliados.

## Dados e segredos

Evidências são sanitizadas na escrita: headers de autorização, cookies, tokens, senhas, chaves e PII não necessária devem ser removidos ou mascarados. Credenciais de teste terão TTL no `CredentialVault`, não aparecerão em logs e serão apagadas ao término do scan. O uso de memória em Python é proteção de melhor esforço, não garantia contra swap ou dump.

## Plataforma web

Quando API e web forem criadas: validação de entrada, cookies seguros, expiração de sessão, proteção CSRF quando aplicável, headers de segurança, CSP, rate limiting, logs estruturados e varredura de dependências entram como requisitos de aceite.
