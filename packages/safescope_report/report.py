"""Portable executive and technical PDF reports for SafeScope."""

from __future__ import annotations

import io
import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from safescope_core.scoring import Confidence, ScoreInput, calculate_security_score

if TYPE_CHECKING:
    from collections.abc import Iterable

ReportKind = Literal["executive", "technical"]


@dataclass(frozen=True)
class ReportEvidence:
    """A safe evidence reference already redacted by the persistence layer."""

    source: str
    url: str
    observed_at: datetime
    sanitized_data: dict[str, Any]


@dataclass(frozen=True)
class ReportFinding:
    """Finding content rendered in a report without ORM coupling."""

    id: str
    title: str
    severity: str
    confidence: float
    status: str
    description: str
    remediation: str | None
    created_at: datetime
    evidence: tuple[ReportEvidence, ...] = ()


@dataclass(frozen=True)
class ReportInput:
    """All data required to create a self-contained local report."""

    organization_name: str
    project_name: str
    target_url: str
    target_verified: bool
    created_at: datetime
    scopes: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    findings: tuple[ReportFinding, ...] = ()
    report_id: str = ""


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEVERITY_COLOR = {
    "CRITICAL": "#8B1E2D",
    "HIGH": "#A64B2A",
    "MEDIUM": "#9A7512",
    "LOW": "#23628F",
    "INFO": "#4B5563",
}


def _confidence(value: float) -> Confidence:
    if value >= 0.9:
        return Confidence.CONFIRMED
    if value >= 0.65:
        return Confidence.LIKELY
    return Confidence.POTENTIAL


def _timestamp(value: datetime) -> str:
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.strftime("%d/%m/%Y %H:%M UTC")


def _safe_text(value: str, limit: int = 1800) -> str:
    """Keep paragraphs printable and bounded without reintroducing raw evidence."""
    return " ".join(value.replace("\x00", "").split())[:limit]


def _score(findings: Iterable[ReportFinding]) -> tuple[int, int]:
    relevant = [item for item in findings if item.status in {"OPEN", "ACKNOWLEDGED"}]
    score = calculate_security_score(ScoreInput(item.severity, _confidence(item.confidence)) for item in relevant)
    return score.value, score.deductions


def _styles() -> dict[str, Any]:
    """Load ReportLab only when an export is actually requested."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "SafeScopeTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=colors.HexColor("#102A43"),
            spaceAfter=12,
        ),
        "subtitle": ParagraphStyle(
            "SafeScopeSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=12,
            leading=18,
            textColor=colors.HexColor("#486581"),
            spaceAfter=18,
        ),
        "heading": ParagraphStyle(
            "SafeScopeHeading",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=21,
            textColor=colors.HexColor("#102A43"),
            spaceBefore=14,
            spaceAfter=8,
        ),
        "subheading": ParagraphStyle(
            "SafeScopeSubheading",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#243B53"),
            spaceBefore=10,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "SafeScopeBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#243B53"),
            spaceAfter=7,
        ),
        "small": ParagraphStyle(
            "SafeScopeSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#627D98"),
            spaceAfter=5,
        ),
        "cover": ParagraphStyle(
            "SafeScopeCover",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=16,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#243B53"),
        ),
    }


def _footer(canvas: Any, document: Any) -> None:
    from reportlab.lib.colors import HexColor
    from reportlab.lib.units import mm

    canvas.saveState()
    canvas.setStrokeColor(HexColor("#D9E2EC"))
    canvas.line(18 * mm, 14 * mm, document.pagesize[0] - 18 * mm, 14 * mm)
    canvas.setFillColor(HexColor("#627D98"))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(18 * mm, 8.5 * mm, "SafeScope - relatório confidencial")
    canvas.drawRightString(document.pagesize[0] - 18 * mm, 8.5 * mm, f"Página {document.page}")
    canvas.restoreState()


def _paragraph(text: str, style: Any) -> Any:
    from reportlab.platypus import Paragraph

    escaped = _safe_text(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(escaped.replace("\n", "<br/>"), style)


def _stat_table(findings: tuple[ReportFinding, ...], score: int, deductions: int, styles: dict[str, Any]) -> Any:
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Table, TableStyle

    counts = Counter(item.severity.upper() for item in findings)
    cells = [
        ("Security Score", str(score), f"-{deductions} pontos"),
        ("Críticos", str(counts["CRITICAL"]), "prioridade máxima"),
        ("Altos", str(counts["HIGH"]), "tratar primeiro"),
        ("Médios", str(counts["MEDIUM"]), "planejar correção"),
    ]
    label_style = styles["small"]
    value_style = ParagraphStyle(
        "SafeScopeStatValue",
        parent=styles["body"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#102A43"),
    )
    data = [
        [Paragraph(f"<b>{label}</b>", label_style) for label, _value, _note in cells],
        [Paragraph(value, value_style) for _label, value, _note in cells],
        [Paragraph(note, label_style) for _label, _value, note in cells],
    ]
    table = Table(data, colWidths=[42 * mm] * 4, hAlign="LEFT", rowHeights=[7 * mm, 10 * mm, 7 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0F4F8")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D9E2EC")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D9E2EC")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    return table


def _severity_tag(finding: ReportFinding, styles: dict[str, Any]) -> Any:
    from reportlab.platypus import Paragraph

    color = _SEVERITY_COLOR.get(finding.severity.upper(), _SEVERITY_COLOR["INFO"])
    text = (
        f'<font color="{color}"><b>{finding.severity.upper()}</b></font> '
        f"- confiança {round(finding.confidence * 100)}% - status {finding.status}"
    )
    return Paragraph(text, styles["small"])


def _evidence_table(evidence: tuple[ReportEvidence, ...], styles: dict[str, Any]) -> Any:
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Table, TableStyle

    rows = [
        [
            Paragraph("Fonte", styles["small"]),
            Paragraph("URL", styles["small"]),
            Paragraph("Observado", styles["small"]),
        ]
    ]
    for item in evidence[:5]:
        rows.append(
            [
                Paragraph(_safe_text(item.source, 90), styles["small"]),
                Paragraph(_safe_text(item.url, 220), styles["small"]),
                Paragraph(_timestamp(item.observed_at), styles["small"]),
            ]
        )
    table = Table(rows, colWidths=[28 * mm, 109 * mm, 35 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E6EEF5")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D9E2EC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def generate_pdf(report: ReportInput, kind: ReportKind) -> bytes:
    """Return an executive or technical PDF report as bytes.

    The generator accepts only normalized, sanitized values. It never reads secrets,
    raw HTTP bodies, or database connections itself.
    """
    if kind not in {"executive", "technical"}:
        raise ValueError(f"Unsupported report kind: {kind}")

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, PageBreak, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = _styles()
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=22 * mm,
        title=f"SafeScope - {kind} report",
        author="SafeScope",
    )
    findings = tuple(
        sorted(report.findings, key=lambda item: (_SEVERITY_ORDER.get(item.severity.upper(), 9), item.title))
    )
    score, deductions = _score(findings)
    counts = Counter(item.severity.upper() for item in findings)
    story: list[Any] = []

    story.extend(
        [
            Spacer(1, 40 * mm),
            _paragraph("SAFE SCOPE", styles["cover"]),
            Spacer(1, 7 * mm),
            _paragraph("Relatório Executivo" if kind == "executive" else "Relatório Técnico", styles["title"]),
            _paragraph("Avaliação externa passiva e não intrusiva", styles["subtitle"]),
            Table(
                [
                    ["Organização", report.organization_name],
                    ["Projeto", report.project_name],
                    ["Target", report.target_url],
                    ["Emitido em", _timestamp(report.created_at)],
                    ["Classificação", "CONFIDENCIAL"],
                ],
                colWidths=[38 * mm, 134 * mm],
                style=TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E6EEF5")),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D9E2EC")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#243B53")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 7),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ]
                ),
            ),
            Spacer(1, 20 * mm),
            _paragraph(
                "Este documento registra observações obtidas apenas por navegação pública normal. "
                "Não houve exploração, autenticação, alteração de dados ou tentativa de acesso não autorizado.",
                styles["body"],
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            _paragraph("Resumo", styles["heading"]),
            _stat_table(findings, score, deductions, styles),
            Spacer(1, 7 * mm),
            _paragraph(
                f"Foram registrados {len(findings)} achados. A pontuação considera apenas findings abertos ou "
                "reconhecidos e "
                "representa indicadores de risco, não prova de exploração.",
                styles["body"],
            ),
            _paragraph("Escopo e limitações", styles["heading"]),
            _paragraph(f"Target avaliado: {report.target_url}", styles["body"]),
            _paragraph(
                "Origens permitidas: " + (", ".join(report.scopes) if report.scopes else report.target_url),
                styles["body"],
            ),
            _paragraph(
                "Exclusões: " + (", ".join(report.exclusions) if report.exclusions else "nenhuma registrada"),
                styles["body"],
            ),
            _paragraph(
                "O escopo desta entrega é PASSIVE. Validações intrusivas, tentativas de login, ataques ativos e "
                "alterações "
                "em sistemas estão fora desta avaliação.",
                styles["body"],
            ),
            _paragraph("Prioridades", styles["heading"]),
        ]
    )
    priority_rows = [["Severidade", "Quantidade", "Tratamento recomendado"]]
    for severity, recommendation in (
        ("CRITICAL", "Tratar imediatamente"),
        ("HIGH", "Prioridade alta"),
        ("MEDIUM", "Planejar correção"),
        ("LOW", "Corrigir em ciclo regular"),
        ("INFO", "Registrar e acompanhar"),
    ):
        priority_rows.append([severity, str(counts[severity]), recommendation])
    priority = Table(priority_rows, colWidths=[35 * mm, 30 * mm, 107 * mm], repeatRows=1)
    priority.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E6EEF5")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D9E2EC")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#243B53")),
                ("ALIGN", (1, 1), (1, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(priority)

    if kind == "executive":
        story.append(_paragraph("Principais achados", styles["heading"]))
        for finding in findings[:10]:
            story.append(
                KeepTogether(
                    [
                        _paragraph(finding.title, styles["subheading"]),
                        _severity_tag(finding, styles),
                        _paragraph(finding.description, styles["body"]),
                        _paragraph(
                            "Recomendação: " + (finding.remediation or "Validar e definir plano de correção."),
                            styles["body"],
                        ),
                    ]
                )
            )
    else:
        story.append(PageBreak())
        story.append(_paragraph("Detalhamento técnico", styles["heading"]))
        for position, finding in enumerate(findings, start=1):
            evidence_json = ""
            if finding.evidence:
                evidence_json = json.dumps(finding.evidence[0].sanitized_data, ensure_ascii=False, sort_keys=True)
            blocks: list[Any] = [
                _paragraph(f"{position}. {finding.title}", styles["subheading"]),
                _severity_tag(finding, styles),
                _paragraph("Descrição: " + finding.description, styles["body"]),
                _paragraph(
                    "Remediação: " + (finding.remediation or "Validar e definir plano de correção."), styles["body"]
                ),
            ]
            if finding.evidence:
                blocks.extend(
                    [
                        _paragraph("Referências de evidência", styles["subheading"]),
                        _evidence_table(finding.evidence, styles),
                        _paragraph("Exemplo sanitizado: " + _safe_text(evidence_json, 600), styles["small"]),
                    ]
                )
            story.append(KeepTogether(blocks))

    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
