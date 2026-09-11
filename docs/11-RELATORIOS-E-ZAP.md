# Relatórios e ZAP Baseline

## Relatórios locais

O SafeScope gera dois PDFs para cada target, sempre a partir de findings e evidências já sanitizadas:

- **Executivo:** Security Score, prioridades, limites e recomendações principais.
- **Técnico:** detalhe de cada finding, status, remediação e referências de evidência.

No dashboard, selecione o target e use os botões de relatório. A API também disponibiliza:

```text
GET /reports/targets/{target_id}/executive.pdf
GET /reports/targets/{target_id}/technical.pdf
GET /reports/targets/{target_id}/proposal.md
GET /reports/targets/{target_id}/roe.md
```

Os templates de proposta e ROE são pontos de partida para revisão comercial e jurídica. Eles não substituem a autorização formal do representante do cliente.

## ZAP Baseline passivo

A integração é opcional e desativada por padrão. O caminho oficial recomendado é instalar o Docker e permitir que ele use a imagem `ghcr.io/zaproxy/zaproxy:stable`, que já contém `zap-baseline.py`. Um lançador `zap-baseline.py` local no `PATH` também é aceito. O status local pode ser consultado em `GET /integrations/zap`.

Ao marcar **Incluir ZAP Baseline passivo** no dashboard, a API só cria o job se houver um runner local. O worker executa somente argumentos fixos: target registrado, relatório JSON temporário, spider limitado e tempo máximo de 300 segundos. Pelo Docker, o container é temporário e executa sem capacidades Linux extras e com `no-new-privileges`. Não existe campo para informar comandos arbitrários.

Antes da execução, o scanner verifica novamente o snapshot imutável: modo `PASSIVE`, `zap-baseline` autorizado, origem permitida e ausência de exclusão. O resultado é convertido em evidências sanitizadas; corpos de resposta e valores de evidência retornados pelo ZAP não são persistidos.

O ZAP continua sendo um processo externo. Use-o apenas para o target explicitamente registrado e reveja os resultados antes de enviar qualquer relatório ao cliente.
