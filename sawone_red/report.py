# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Self-contained HTML report with a branded cover, summary and findings."""

from __future__ import annotations

from html import escape

from . import __version__
from .owasp import OWASP_LLM_TOP10
from .probes import SEVERITIES
from .runner import RunResult

COPYRIGHT = "Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License."

CSS = """
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1c1c24; background: #f5f5f7; }
.cover { background: radial-gradient(circle at 85% 0%, #4a0d15 0%, #0b0b0f 58%); color: #f5f5f7; padding: 56px 48px 44px; }
.cover .brand { letter-spacing: 0.32em; font-weight: 700; color: #e11d2e; font-size: 13px; }
.cover h1 { margin: 12px 0 4px; font-size: 40px; }
.cover .sub { color: #b5b5c0; font-size: 16px; }
.cover dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 18px; margin: 28px 0 0; color: #d8d8e0; }
.cover dt { color: #8d8d99; }
.cover dd { margin: 0; word-break: break-all; }
main { max-width: 1040px; margin: 0 auto; padding: 32px 24px 56px; }
h2 { font-size: 20px; margin: 36px 0 12px; border-bottom: 2px solid #e11d2e; padding-bottom: 6px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.card { background: #fff; border-radius: 10px; padding: 16px; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.06); }
.card .value { font-size: 26px; font-weight: 700; }
.card .label { color: #6b6b78; font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #ececf1; vertical-align: top; }
th { background: #fafafc; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #6b6b78; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase; color: #fff; margin-right: 6px; }
.sev-critical { background: #7f1d1d; }
.sev-high { background: #e11d2e; }
.sev-medium { background: #d97706; }
.sev-low { background: #2563eb; }
.sev-info { background: #6b7280; }
.finding { background: #fff; border-radius: 10px; padding: 18px 20px; margin-bottom: 14px; border-left: 5px solid #e11d2e; }
.finding h3 { margin: 8px 0 10px; font-size: 16px; }
.finding dl { display: grid; grid-template-columns: 150px 1fr; gap: 8px 14px; margin: 0; }
.finding dt { color: #6b6b78; }
.finding dd { margin: 0; min-width: 0; }
pre { background: #0b0b0f; color: #e6e6ee; padding: 10px 12px; border-radius: 6px; white-space: pre-wrap; word-break: break-word; font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; margin: 0; }
.muted { color: #6b6b78; }
footer { color: #6b6b78; font-size: 12px; text-align: center; padding: 24px; }
@media (max-width: 600px) {
  .cover { padding: 36px 20px; }
  .cover h1 { font-size: 30px; }
  .finding dl { grid-template-columns: 1fr; }
}
"""


def render_html(run: RunResult) -> str:
    parts = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Sawone Red report - {escape(run.config_name)}</title>",
        f"<style>{CSS}</style>",
        "</head>",
        "<body>",
        _cover(run),
        "<main>",
        _summary(run),
        _owasp_table(run),
        _findings(run),
        _results_table(run),
        "</main>",
        _footer(),
        "</body>",
        "</html>",
    ]
    return "\n".join(parts) + "\n"


def _cover(run: RunResult) -> str:
    rows = [
        ("Target", run.target),
        ("Configuration", run.config_path),
        ("Run started (UTC)", run.started_at),
        ("Seed", run.seed),
    ]
    items = "".join(f"<dt>{escape(key)}</dt><dd>{escape(value)}</dd>" for key, value in rows)
    return (
        '<header class="cover">'
        '<div class="brand">SAWONE RED</div>'
        "<h1>AI Red-Team Report</h1>"
        f'<div class="sub">{escape(run.config_name)}</div>'
        f"<dl>{items}</dl>"
        "</header>"
    )


def _summary(run: RunResult) -> str:
    cards = [
        ("Risk score", f"{run.score}/100"),
        ("Risk rating", run.rating),
        ("Probes executed", str(run.executed)),
        ("Findings", str(len(run.findings))),
        ("Passed", str(run.passed)),
        ("Errors", str(run.errors)),
        ("Skipped", str(run.skipped)),
    ]
    card_html = "".join(
        f'<div class="card"><div class="value">{escape(value)}</div><div class="label">{escape(label)}</div></div>'
        for label, value in cards
    )
    badges = "".join(
        f'<span class="badge sev-{severity}">{severity} {count}</span>'
        for severity, count in _severity_counts(run)
    )
    sentence = (
        f"{len(run.findings)} of {run.executed} executed probes showed a failed control."
        if run.executed
        else "No probe reached the target."
    )
    return (
        "<h2>Executive summary</h2>"
        f'<div class="cards">{card_html}</div>'
        f"<p>{escape(sentence)}</p>"
        f"<p>{badges or '<span class=\"muted\">No findings by severity.</span>'}</p>"
        '<p class="muted">Authorized testing only. This report records control failures. '
        "Probes plant benign markers and canary tokens, so it contains no harmful content by design.</p>"
    )


def _owasp_table(run: RunResult) -> str:
    rows = []
    for code, title in OWASP_LLM_TOP10.items():
        executed = [r for r in run.results if r.owasp == code and r.status in ("pass", "fail")]
        if not executed:
            continue
        failed = sum(r.status == "fail" for r in executed)
        rows.append(
            f"<tr><td>{escape(code)}</td><td>{escape(title)}</td>"
            f"<td>{len(executed)}</td><td>{failed}</td></tr>"
        )
    body = "".join(rows) or '<tr><td colspan="4" class="muted">No probes executed.</td></tr>'
    return (
        "<h2>OWASP LLM Top 10 coverage</h2>"
        '<div class="table-wrap"><table>'
        "<thead><tr><th>Category</th><th>Title</th><th>Probes</th><th>Failed</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
    )


def _findings(run: RunResult) -> str:
    if not run.findings:
        return "<h2>Findings</h2><p>No failed controls were observed.</p>"
    ordered = sorted(run.findings, key=lambda r: SEVERITIES.index(r.severity), reverse=True)
    cards = []
    for result in ordered:
        cards.append(
            f'<article class="finding">'
            f'<span class="badge sev-{escape(result.severity)}">{escape(result.severity)}</span>'
            f'<span class="muted">{escape(result.probe_id)} | {escape(result.owasp)}</span>'
            f"<h3>{escape(result.name)}</h3>"
            "<dl>"
            f"<dt>Detector verdict</dt><dd>{escape(result.evidence)} (detector: {escape(result.detector)})</dd>"
            f"<dt>Probe prompt</dt><dd><pre>{escape(result.prompt)}</pre></dd>"
            f"<dt>Response excerpt</dt><dd><pre>{escape(result.excerpt) or '(none)'}</pre></dd>"
            f"<dt>Remediation</dt><dd>{escape(result.remediation)}</dd>"
            "</dl>"
            "</article>"
        )
    return "<h2>Findings</h2>" + "".join(cards)


def _results_table(run: RunResult) -> str:
    rows = []
    for result in run.results:
        if result.status == "fail":
            continue
        rows.append(
            f"<tr><td>{escape(result.probe_id)}</td><td>{escape(result.name)}</td>"
            f"<td>{escape(result.status)}</td><td>{escape(result.evidence)}</td></tr>"
        )
    if not rows:
        return ""
    return (
        "<h2>Controls that held or were not run</h2>"
        '<div class="table-wrap"><table>'
        "<thead><tr><th>ID</th><th>Probe</th><th>Status</th><th>Detail</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _severity_counts(run: RunResult) -> list[tuple[str, int]]:
    counts = []
    for severity in reversed(SEVERITIES):
        count = sum(1 for r in run.findings if r.severity == severity)
        if count:
            counts.append((severity, count))
    return counts


def _footer() -> str:
    return (
        f"<footer>Sawone Red {escape(__version__)}. Report for authorized testing only.<br>"
        f"{escape(COPYRIGHT)}</footer>"
    )
