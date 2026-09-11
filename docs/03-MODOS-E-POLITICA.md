# Modos e política de execução

## PASSIVE

Aceita alvo ainda não verificado. Permite somente observação pública com GET/HEAD normal: TLS, certificados, headers, cookies observáveis, CORS observado, tecnologias expostas e arquivos publicados pelo próprio site. É proibido autenticar, enumerar contas, enviar payloads, fazer fuzzing, escrever dados ou realizar tentativas de acesso.

## GUIDED

Exige alvo verificado e autorização vigente. Serve para validações leves explicitamente permitidas. O teto de risco é `LIGHT` e permanece sujeito a orçamento, taxa, exclusões e kill switch.

## AGGRESSIVE

Só existe com autorização formal (ROE), representante identificado, escopo, exclusões, janela de tempo, limites de volume e métodos permitidos. Mesmo nesse modo não há caminho para exfiltração, persistência ou dano. Operações de escrita dependem de `allow_mutations`, caminhos permitidos e ledger de recursos. A liberação é feita pelo backend, nunca apenas pela interface.

## Ordem de decisão

1. O scanner respeita o teto do modo.
2. Scanner não passivo exige alvo verificado, autorização vigente e origem no escopo.
3. Cada requisição passa por kill switch, orçamento, esquema, origem, exclusões e verbo.
4. Escrita exige autorização específica e ledger/snapshot.
5. O transporte valida o IP resolvido contra SSRF antes de conectar.
