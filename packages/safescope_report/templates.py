"""Commercial templates that reinforce authorized and defensive work."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class EngagementTemplateInput:
    organization_name: str
    project_name: str
    target_url: str
    generated_at: datetime


def _date(value: datetime) -> str:
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.strftime("%d/%m/%Y")


def proposal_markdown(data: EngagementTemplateInput) -> str:
    """Create a neutral proposal template without promising intrusive work."""
    return f"""# Proposta de auditoria de segurança

**Organização:** {data.organization_name}

**Projeto:** {data.project_name}

**Target inicial:** {data.target_url}

**Emitida em:** {_date(data.generated_at)}

## Objetivo

Realizar uma avaliação de segurança conforme escopo, janela e métodos acordados por escrito.
A etapa inicial é passiva e não intrusiva.

## Entregáveis

- Resumo executivo de riscos e prioridades.
- Relatório técnico com evidências sanitizadas e recomendações.
- Reunião de apresentação dos resultados.
- Reteste, caso seja contratado e autorizado.

## Limites

Nenhum acesso não autorizado, exploração, alteração de dados, indisponibilidade deliberada ou tentativa de autenticação
será realizada sem ROE válida, verificação de domínio e escopo explícito.

## Próximos passos

1. Confirmar objetivo, contatos e escopo.
2. Definir proposta comercial e janela de avaliação.
3. Assinar a ROE antes de qualquer teste além do modo passivo.
"""


def roe_markdown(data: EngagementTemplateInput) -> str:
    """Create a Rules of Engagement template for review and signature."""
    return f"""# Regras de Engajamento (ROE)

**Organização:** {data.organization_name}

**Projeto:** {data.project_name}

**Target:** {data.target_url}

**Preparada em:** {_date(data.generated_at)}

## Autorização

O representante autorizado declara que possui poder para autorizar a avaliação dos ativos listados neste documento,
exclusivamente dentro do escopo e da janela aprovados.

**Representante:** ________________________________________

**Cargo:** _________________________________________________

**E-mail:** ________________________________________________

**Assinatura e data:** _____________________________________

## Escopo autorizado

- Origens permitidas: ______________________________________
- Caminhos excluídos: ______________________________________
- Ambiente: produção / homologação / outro: ________________
- Janela de avaliação: _____________________________________
- Métodos permitidos: ______________________________________

## Restrições obrigatórias

- Não executar testes fora do escopo escrito.
- Não acessar, exfiltrar ou reter dados pessoais além do mínimo necessário para evidência.
- Não causar indisponibilidade, persistência ou alteração de dados sem autorização específica adicional.
- Interromper o trabalho ao receber solicitação do contato indicado.

## Contato de emergência

Nome: ______________________________________________________

Telefone: __________________________________________________

E-mail: ____________________________________________________
"""
