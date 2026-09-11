"""Safe parsing and policy checks for the optional ZAP Baseline adapter."""

from __future__ import annotations

import asyncio

from safescope_core.policy import ResourceLedger
from safescope_scanners.base import ScanContext, Severity
from safescope_scanners.zap import (
    ZapBaselineScanner,
    _command,
    _policy_allows,
    _Runner,
    parse_zap_report,
)


def test_zap_report_is_converted_without_raw_evidence() -> None:
    observations = parse_zap_report(
        {
            "site": [
                {
                    "@name": "https://example.com",
                    "alerts": [
                        {
                            "alert": "Missing CSP",
                            "riskcode": "2",
                            "confidence": "High",
                            "desc": "<p>A header is missing.</p>",
                            "solution": "<p>Add a policy.</p>",
                            "pluginid": "10038",
                            "alertRef": "10038-1",
                            "instances": [
                                {
                                    "uri": "https://example.com",
                                    "method": "GET",
                                    "evidence": "session=secret-value",
                                }
                            ],
                        }
                    ],
                }
            ]
        },
        "https://fallback.example",
    )

    assert len(observations) == 1
    observation = observations[0]
    assert observation.severity is Severity.MEDIUM
    assert observation.url == "https://example.com"
    assert observation.evidence == {
        "alert_ref": "10038-1",
        "plugin_id": "10038",
        "risk": "",
        "method": "GET",
    }
    assert "secret-value" not in str(observation.evidence)


def test_zap_requires_the_frozen_passive_allowlist() -> None:
    context = ScanContext(
        "https://example.com",
        http=None,
        ledger=ResourceLedger("test"),
        metadata={
            "policy_snapshot": {
                "mode": "PASSIVE",
                "scanners_allowed": ["zap-baseline"],
                "allowed_origins": ["https://example.com"],
                "excluded": [],
            }
        },
    )
    assert _policy_allows(context) is True

    context.metadata["policy_snapshot"]["excluded"] = ["https://example.com*"]
    assert _policy_allows(context) is False


def test_zap_launcher_uses_a_local_fixed_baseline_wrapper(tmp_path, monkeypatch) -> None:
    launcher = tmp_path / "zap-baseline.py"
    launcher.write_text(
        "\n".join(
            [
                "#!/usr/bin/python3",
                "import json, pathlib, sys",
                "report = pathlib.Path(sys.argv[sys.argv.index('-J') + 1])",
                "target = sys.argv[sys.argv.index('-t') + 1]",
                "payload = {'site': [{'alerts': [{'alert': 'ZAP test', 'riskcode': '1',",
                "'instances': [{'uri': target, 'method': 'GET'}]}]}]}",
                "report.write_text(json.dumps(payload))",
            ]
        ),
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    context = ScanContext(
        "https://example.com",
        http=None,
        ledger=ResourceLedger("test"),
        metadata={
            "policy_snapshot": {
                "mode": "PASSIVE",
                "scanners_allowed": ["zap-baseline"],
                "allowed_origins": ["https://example.com"],
                "excluded": [],
            }
        },
    )

    observations = asyncio.run(ZapBaselineScanner().scan(context))

    assert observations[0].title == "ZAP test"
    assert observations[0].severity is Severity.LOW
    assert observations[0].url == "https://example.com"


def test_zap_docker_command_uses_the_official_image_and_fixed_arguments(tmp_path) -> None:
    command = _command(
        _Runner("/usr/bin/docker", uses_docker=True),
        "https://example.com",
        tmp_path / "baseline.json",
        tmp_path,
    )

    assert command[:5] == [
        "/usr/bin/docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ]
    assert "ghcr.io/zaproxy/zaproxy:stable" in command
    assert command[-10:] == [
        "zap-baseline.py",
        "-t",
        "https://example.com",
        "-J",
        "/zap/wrk/baseline.json",
        "-m",
        "1",
        "-T",
        "2",
        "-I",
    ]
