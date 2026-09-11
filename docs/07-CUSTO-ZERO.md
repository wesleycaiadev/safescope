# Operação inicial sem custo fixo

O MVP roda no computador do analista: Python, SQLite, FastAPI, Next.js, Docker opcional, OWASP ZAP Baseline, Semgrep, pip-audit, npm audit e OSV Scanner são ferramentas que podem ser usadas sem custo de licença no desenvolvimento. A prioridade é não depender de serviços pagos antes dos primeiros clientes.

| Necessidade | MVP | Evolução quando houver receita |
| --- | --- | --- |
| Banco | SQLite local | PostgreSQL/Supabase |
| Execução | Worker no notebook | Worker dedicado |
| Autenticação | Local para desenvolvimento | Supabase Auth / provedor adequado |
| Dashboard | Local | Hospedagem compatível com uso comercial |
| Relatórios | HTML/Markdown local | PDF profissional |

Planos gratuitos e cotas mudam. Antes de hospedar dados de clientes ou vender o serviço, confirmar termos de uso, limites, LGPD e custo da infraestrutura escolhida. Domínio e infraestrutura de produção são decisões comerciais posteriores, não pressupostos do MVP.
