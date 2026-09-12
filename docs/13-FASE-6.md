# Fase 6 — testes autenticados controlados

## Estado

A Fase 6 está concluída como fundação segura. Ela não transforma o dashboard em
um disparador irrestrito de ataques: jobs públicos continuam passivos e os
scanners ativos só operam quando recebem canários, identidades e allowlists
explícitas de uma ROE válida.

O login mencionado nesta fase pertence ao site auditado, não ao SafeScope. O
painel continua de usuário único. Cada identidade do alvo recebe um canal e um
cookie jar separados; os segredos vivem no `CredentialVault`, são substituídos
somente no momento da requisição e são apagados ao final do run.

## Componentes

- `session.py`: login declarativo, health probe, relogin limitado e limpeza.
- `discovery.py`: ingere OpenAPI, schema GraphQL já fornecido e caminhos de JS;
  não executa automaticamente os candidatos e descarta origens fora do escopo.
- `oracles.py`: compara baseline, controle negativo e probe; evidências guardam
  somente status, tamanho e hash, nunca o corpo bruto.
- `mutations.py`: grava a restauração antes da escrita. `DELETE` continua
  permitido apenas para recurso-canário criado pelo próprio scan.
- `worker/restore_journal.py`: arquivos atômicos com permissões `0600`, tentativas
  limitadas e replay antes de um novo job.
- `razor/authorization.py`: IDOR e matriz de autorização somente sobre canários.
- `pacing.py`: jitter, modo suave após `403/429` repetidos e concorrência limitada.
- `lab/`: alvo FastAPI deliberadamente vulnerável e rota equivalente corrigida,
  permitindo medir o caso positivo e o falso positivo.

## Executar o gabarito

```bash
make lab-test
```

Para inspecionar o alvo em Docker:

```bash
make lab-up
# abrir http://127.0.0.1:8090/docs
make lab-down
```

O contêiner é publicado somente no loopback, roda sem capabilities, com sistema
de arquivos somente leitura e `no-new-privileges`.

## Limites deliberados

- O dashboard não dispara scanners ativos.
- Não existe enumeração automática de IDs reais.
- Não existem payloads SQLi, SSRF, XSS, evasão de WAF ou destruição.
- Novos scanners precisam usar `RequestGate`, controle negativo, evidência
  sanitizada, laboratório conhecido e limpeza comprovada.
- Para testar autorização horizontal são necessárias duas contas de teste do
  alvo; uma única conta não consegue provar que o usuário A acessa dados de B.
