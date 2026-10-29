# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""JSON, Markdown and SARIF 2.1.0 outputs, plus the report writer."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .probes import SEVERITIES
from .report import COPYRIGHT, render_html
from .runner import ProbeResult, RunResult

TOOL_NAME = "Sawone Red"
TOOL_URI = "https://github.com/hackin2minutes-oss/sawone-red"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.5"}


def to_json(run: RunResult) -> str:
    payload = {
        "tool": {"name": TOOL_NAME, "version": __version__},
        "run": {
            "config": run.config_path,
            "name": run.config_name,
            "target": run.target,
            "seed": run.seed,
            "started_at": run.started_at,
        },
        "summary": {
            "executed": run.executed,
            "findings": len(run.findings),
            "passed": run.passed,
            "errors": run.errors,
            "skipped": run.skipped,
            "risk_score": run.score,
            "risk_rating": run.rating,
        },
        "results": [asdict(result) for result in run.results],
    }
    return json.dumps(payload, indent=2) + "\n"


def to_markdown(run: RunResult) -> str:
    lines = [
        f"# Sawone Red report: {run.config_name}",
        "",
        f"- Target: {run.target}",
        f"- Started (UTC): {run.started_at}",
        f"- Risk score: {run.score}/100 ({run.rating})",
        f"- Probes executed: {run.executed}; findings: {len(run.findings)}; "
        f"errors: {run.errors}; skipped: {run.skipped}",
        "",
    ]
    if not run.findings:
        lines.append("No failed controls were observed.")
    else:
        lines += ["## Findings", "", "| ID | Severity | OWASP | Probe | Verdict |", "| --- | --- | --- | --- | --- |"]
        for result in _ordered(run.findings):
            lines.append(
                f"| {result.probe_id} | {result.severity} | {result.owasp} | "
                f"{_cell(result.name)} | {_cell(result.evidence)} |"
            )
        lines += ["", "## Remediation", ""]
        for result in _ordered(run.findings):
            lines.append(f"- **{result.probe_id}**: {result.remediation}")
    lines += ["", "---", "", COPYRIGHT]
    return "\n".join(lines) + "\n"


def to_sarif(run: RunResult) -> dict:
    """SARIF 2.1.0 for GitHub code scanning. Each failed probe is one result."""
    uri = Path(run.config_path).as_posix()
    rules: dict[str, dict] = {}
    results = []
    for result in _ordered(run.findings):
        rules.setdefault(result.probe_id, _sarif_rule(result))
        results.append(
            {
                "ruleId": result.probe_id,
                "level": SARIF_LEVEL[result.severity],
                "message": {"text": f"{result.name}: {result.evidence}. {result.remediation}"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}
                ],
                "partialFingerprints": {
                    "sawoneRed/v1": hashlib.sha256(f"{run.target}|{result.probe_id}".encode("utf-8")).hexdigest()
                },
                "properties": {"severity": result.severity, "owasp": result.owasp, "target": run.target},
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [{"executionSuccessful": run.executed > 0}],
                "results": results,
            }
        ],
    }


def write_reports(
    run: RunResult,
    output_dir: str,
    formats: tuple,
    sarif_path: str | None = None,
) -> dict[str, str]:
    directory = Path(output_dir)
    written: dict[str, str] = {}
    if "html" in formats:
        written["html"] = _write(directory / "report.html", render_html(run))
    if "json" in formats:
        written["json"] = _write(directory / "results.json", to_json(run))
    if "markdown" in formats:
        written["markdown"] = _write(directory / "report.md", to_markdown(run))
    if sarif_path:
        written["sarif"] = _write(Path(sarif_path), _sarif_text(run))
    elif "sarif" in formats:
        written["sarif"] = _write(directory / "results.sarif", _sarif_text(run))
    return written


def _sarif_text(run: RunResult) -> str:
    return json.dumps(to_sarif(run), indent=2) + "\n"


def _sarif_rule(result: ProbeResult) -> dict:
    return {
        "id": result.probe_id,
        "name": result.name,
        "shortDescription": {"text": result.name},
        "fullDescription": {"text": f"{result.name}. Detector: {result.detector}."},
        "help": {"text": result.remediation},
        "defaultConfiguration": {"level": SARIF_LEVEL[result.severity]},
        "properties": {
            "tags": ["security", "ai", result.owasp],
            "security-severity": SECURITY_SEVERITY[result.severity],
        },
    }


def _ordered(results: list[ProbeResult]) -> list[ProbeResult]:
    return sorted(results, key=lambda r: SEVERITIES.index(r.severity), reverse=True)


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _write(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)
