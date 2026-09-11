"""Constrained OWASP ZAP Baseline adapter.

ZAP Baseline is opt-in and never receives a user supplied shell command. It is
only selected when the frozen scan policy explicitly contains ``zap-baseline``.
"""

from __future__ import annotations

import asyncio
import fnmatch
import html
import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safescope_core.policy import Risk

from .base import RawObservation, ScanContext, Scanner, Severity

_ZAP_EXECUTABLE = "zap-baseline.py"
_DOCKER_EXECUTABLE = "docker"
_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
_TIMEOUT_SECONDS = 300
_HTML_TAG = re.compile(r"<[^>]+>")
_RISK = {"0": Severity.INFO, "1": Severity.LOW, "2": Severity.MEDIUM, "3": Severity.HIGH}


@dataclass(frozen=True)
class _Runner:
    executable: str
    uses_docker: bool


def zap_available() -> bool:
    """Return whether either supported, fixed ZAP runner is locally callable."""
    return shutil.which(_ZAP_EXECUTABLE) is not None or shutil.which(_DOCKER_EXECUTABLE) is not None


def _runner() -> _Runner:
    executable = shutil.which(_ZAP_EXECUTABLE)
    if executable is not None:
        return _Runner(executable, uses_docker=False)
    docker = shutil.which(_DOCKER_EXECUTABLE)
    if docker is not None:
        return _Runner(docker, uses_docker=True)
    raise RuntimeError("OWASP ZAP Baseline requires zap-baseline.py or Docker on PATH")


def _command(runner: _Runner, target_url: str, report_path: Path, workdir: Path) -> list[str]:
    """Build a fixed argv list. No user value can become a shell command."""
    arguments = ["-t", target_url, "-J", str(report_path), "-m", "1", "-T", "2", "-I"]
    if not runner.uses_docker:
        return [runner.executable, *arguments]
    container_report = "/zap/wrk/baseline.json"
    return [
        runner.executable,
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "-v",
        f"{workdir.resolve()}:/zap/wrk:rw",
        _ZAP_IMAGE,
        _ZAP_EXECUTABLE,
        "-t",
        target_url,
        "-J",
        container_report,
        "-m",
        "1",
        "-T",
        "2",
        "-I",
    ]


def _text(value: object) -> str:
    return " ".join(html.unescape(_HTML_TAG.sub(" ", str(value or ""))).split())


def _severity(alert: dict[str, Any]) -> Severity:
    code = str(alert.get("riskcode", "0"))
    if code in _RISK:
        return _RISK[code]
    prefix = str(alert.get("riskdesc", "")).upper()
    for name, severity in (("HIGH", Severity.HIGH), ("MEDIUM", Severity.MEDIUM), ("LOW", Severity.LOW)):
        if name in prefix:
            return severity
    return Severity.INFO


def _confidence(alert: dict[str, Any]) -> float:
    raw = str(alert.get("confidence", "")).upper()
    return {"CONFIRMED": 1.0, "HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4}.get(raw, 0.4)


def parse_zap_report(payload: dict[str, Any], fallback_url: str) -> list[RawObservation]:
    """Convert ZAP's JSON report into safe, non-sensitive observations."""
    observations: list[RawObservation] = []
    sites = payload.get("site", [])
    if not isinstance(sites, list):
        return observations
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances", [])
            first = instances[0] if isinstance(instances, list) and instances else {}
            if not isinstance(first, dict):
                first = {}
            title = _text(alert.get("alert")) or "ZAP Baseline observation"
            observations.append(
                RawObservation(
                    title=title,
                    severity=_severity(alert),
                    url=str(first.get("uri") or site.get("@name") or fallback_url),
                    detail=_text(alert.get("desc")) or "ZAP Baseline returned an observation.",
                    confidence=_confidence(alert),
                    evidence={
                        "alert_ref": str(alert.get("alertRef", "")),
                        "plugin_id": str(alert.get("pluginid", "")),
                        "risk": str(alert.get("riskdesc", "")),
                        "method": str(first.get("method", "")),
                    },
                    remediation=_text(alert.get("solution")) or None,
                    references=[_text(alert.get("reference"))] if alert.get("reference") else [],
                )
            )
    return observations


def _policy_allows(context: ScanContext) -> bool:
    snapshot = context.metadata.get("policy_snapshot", {})
    if not isinstance(snapshot, dict):
        return False
    if snapshot.get("mode") != "PASSIVE":
        return False
    if "zap-baseline" not in snapshot.get("scanners_allowed", []):
        return False
    if context.target_base_url not in snapshot.get("allowed_origins", []):
        return False
    return not any(fnmatch.fnmatch(context.target_base_url, str(pattern)) for pattern in snapshot.get("excluded", []))


class ZapBaselineScanner(Scanner):
    """Run the official passive ZAP Baseline launcher with fixed arguments."""

    id = "zap-baseline"
    name = "OWASP ZAP Baseline"
    risk = Risk.PASSIVE
    budget_units = 30

    async def scan(self, ctx: ScanContext) -> list[RawObservation]:
        if not _policy_allows(ctx):
            raise RuntimeError("ZAP Baseline is not permitted by the frozen passive policy")
        runner = _runner()
        with tempfile.TemporaryDirectory(prefix="safescope-zap-") as directory:
            workdir = Path(directory)
            report_path = workdir / "baseline.json"
            process = await asyncio.create_subprocess_exec(
                *_command(runner, ctx.target_base_url, report_path, workdir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(process.communicate(), timeout=_TIMEOUT_SECONDS)
            except TimeoutError as error:
                process.kill()
                await process.wait()
                raise RuntimeError("ZAP Baseline exceeded its 300 second limit") from error
            if not report_path.is_file():
                raise RuntimeError("ZAP Baseline did not produce its JSON report")
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("ZAP Baseline produced an invalid JSON report")
        return parse_zap_report(payload, ctx.target_base_url)
