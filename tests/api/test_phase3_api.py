"""End-to-end API coverage for the local Phase 3 control plane."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from apps.api import main as api_main
from apps.api.auth import Principal, current_principal
from safescope_core.models import Finding, create_engine, create_session_factory


def test_phase3_crud_queue_summary_and_finding_workflow(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'api.db'}"
    test_engine = create_engine(database_url)
    test_sessions = create_session_factory(test_engine)
    monkeypatch.setattr(api_main, "engine", test_engine)
    monkeypatch.setattr(api_main, "session_factory", test_sessions)

    with TestClient(api_main.app) as client:
        assert client.get("/health").json() == {"status": "ok"}

        organization = client.post("/organizations", json={"name": "Acme"}).json()
        members = client.get(f"/organizations/{organization['id']}/members")
        assert members.status_code == 200
        assert members.json()[0]["role"] == "OWNER"
        assert members.json()[0]["user_id"] == "local-developer"
        project = client.post(
            "/projects",
            json={"organization_id": organization["id"], "name": "Portal"},
        ).json()
        target_response = client.post(
            "/targets",
            json={"project_id": project["id"], "base_url": "https://example.com"},
        )
        assert target_response.status_code == 201
        target = target_response.json()

        scope_response = client.post(
            "/scopes",
            json={"target_id": target["id"], "origin": "https://example.com"},
        )
        assert scope_response.status_code == 201
        assert scope_response.json()["allowed_verbs"] == ["GET", "HEAD"]
        assert (
            client.post(
                "/scopes",
                json={"target_id": target["id"], "origin": "https://unrelated.example"},
            ).status_code
            == 422
        )

        now = datetime.now(UTC)
        authorization_response = client.post(
            "/authorizations",
            json={
                "target_id": target["id"],
                "representative_name": "Alice",
                "representative_email": "alice@example.com",
                "valid_from": now.isoformat(),
                "valid_until": (now + timedelta(days=7)).isoformat(),
            },
        )
        assert authorization_response.status_code == 201
        assert authorization_response.json()["active_testing"] is False

        job_response = client.post("/scan-jobs", json={"target_id": target["id"]})
        assert job_response.status_code == 201
        assert job_response.json()["status"] == "PENDING"
        assert client.post("/scan-jobs", json={"target_id": target["id"]}).status_code == 409

        async def add_finding() -> str:
            async with test_sessions() as session:
                finding = Finding(
                    target_id=target["id"],
                    title="Missing header",
                    severity="MEDIUM",
                    confidence=0.9,
                    description="A response header is absent.",
                    remediation="Add the response header.",
                )
                session.add(finding)
                await session.commit()
                return finding.id

        finding_id = asyncio.run(add_finding())
        summary = client.get("/summary").json()
        assert summary["targets"] == 1
        assert summary["pending_jobs"] == 1
        assert summary["open_findings"] == 1
        assert summary["score"] == 90

        update_response = client.patch(
            f"/findings/{finding_id}",
            json={"status": "FIXED"},
        )
        assert update_response.status_code == 200
        assert update_response.json()["status"] == "FIXED"
        assert client.get(f"/findings/{finding_id}/evidence").json() == []

        executive = client.get(f"/reports/targets/{target['id']}/executive.pdf")
        technical = client.get(f"/reports/targets/{target['id']}/technical.pdf")
        assert executive.status_code == 200
        assert executive.headers["content-type"] == "application/pdf"
        assert executive.content.startswith(b"%PDF")
        assert technical.content.startswith(b"%PDF")
        assert len(technical.content) > len(executive.content)
        assert "Proposta de auditoria" in client.get(f"/reports/targets/{target['id']}/proposal.md").text
        assert "Regras de Engajamento" in client.get(f"/reports/targets/{target['id']}/roe.md").text
        assert any(item["action"] == "PASSIVE_SCAN_ENQUEUED" for item in client.get("/audit-logs").json())


def test_production_actor_cannot_read_another_organization(tmp_path, monkeypatch) -> None:
    test_engine = create_engine(f"sqlite:///{tmp_path / 'tenant.db'}")
    test_sessions = create_session_factory(test_engine)
    monkeypatch.setattr(api_main, "engine", test_engine)
    monkeypatch.setattr(api_main, "session_factory", test_sessions)
    actor_one = Principal("11111111-1111-1111-1111-111111111111", "one@example.test", True)
    actor_two = Principal("22222222-2222-2222-2222-222222222222", "two@example.test", True)
    api_main.app.dependency_overrides[current_principal] = lambda: actor_one
    try:
        with TestClient(api_main.app) as client:
            organization = client.post("/organizations", json={"name": "Tenant One"}).json()
            api_main.app.dependency_overrides[current_principal] = lambda: actor_two
            assert client.get("/organizations").json() == []
            assert client.get(f"/organizations/{organization['id']}/members").status_code == 404
    finally:
        api_main.app.dependency_overrides.clear()
        asyncio.run(test_engine.dispose())
