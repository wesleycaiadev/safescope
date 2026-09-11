"""Report generation and defensively worded engagement templates."""

from .report import ReportEvidence, ReportFinding, ReportInput, generate_pdf
from .templates import EngagementTemplateInput, proposal_markdown, roe_markdown

__all__ = [
    "EngagementTemplateInput",
    "ReportEvidence",
    "ReportFinding",
    "ReportInput",
    "generate_pdf",
    "proposal_markdown",
    "roe_markdown",
]
