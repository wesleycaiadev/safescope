"""PDF and commercial template coverage for Phase 4."""

from __future__ import annotations

from datetime import UTC, datetime

from safescope_report import (
    EngagementTemplateInput,
    ReportEvidence,
    ReportFinding,
    ReportInput,
    generate_pdf,
    proposal_markdown,
    roe_markdown,
)


def _input() -> ReportInput:
    observed_at = datetime(2026, 9, 10, 14, 0, tzinfo=UTC)
    finding = ReportFinding(
        id="F-1",
        title="Content Security Policy permissiva",
        severity="MEDIUM",
        confidence=0.9,
        status="OPEN",
        description="A política permite fontes amplas.",
        remediation="Restringir as fontes aos domínios necessários.",
        created_at=observed_at,
        evidence=(
            ReportEvidence(
                source="headers",
                url="https://example.com",
                observed_at=observed_at,
                sanitized_data={"csp": "default-src *", "token": "[REDACTED]"},
            ),
        ),
    )
    return ReportInput(
        organization_name="Acme LTDA",
        project_name="Avaliação de setembro",
        target_url="https://example.com",
        target_verified=False,
        created_at=observed_at,
        scopes=("https://example.com",),
        exclusions=("https://example.com/admin/*",),
        findings=(finding,),
        report_id="R-1",
    )


def test_generates_executive_and_technical_pdfs(tmp_path) -> None:
    report = _input()
    executive = generate_pdf(report, "executive")
    technical = generate_pdf(report, "technical")
    executive_path = tmp_path / "executive.pdf"
    technical_path = tmp_path / "technical.pdf"
    executive_path.write_bytes(executive)
    technical_path.write_bytes(technical)

    assert executive.startswith(b"%PDF")
    assert technical.startswith(b"%PDF")
    assert executive_path.stat().st_size > 2_000
    assert technical_path.stat().st_size > executive_path.stat().st_size


def test_proposal_and_roe_templates_preserve_authorization_limits() -> None:
    data = EngagementTemplateInput(
        organization_name="Acme LTDA",
        project_name="Avaliação de setembro",
        target_url="https://example.com",
        generated_at=datetime(2026, 9, 10, tzinfo=UTC),
    )

    proposal = proposal_markdown(data)
    roe = roe_markdown(data)

    assert "nenhum acesso não autorizado" in proposal.lower()
    assert "ROE válida" in proposal
    assert "interromper o trabalho" in roe.lower()
    assert "https://example.com" in roe
