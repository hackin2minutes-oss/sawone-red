# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
import json

from sawone_red.config import load_config
from sawone_red.outputs import to_json, to_sarif, write_reports
from sawone_red.report import render_html
from sawone_red.runner import run


def _vulnerable_run(write_config):
    path = write_config(
        "target:\n  type: mock\n  mode: vulnerable\ncanary: SRCANARY-7A3F9B21C0DE4E55\nseed: t\n"
    )
    return run(load_config(path))


def test_sarif_has_2_1_0_shape_and_one_result_per_finding(write_config):
    result = _vulnerable_run(write_config)
    sarif = to_sarif(result)
    assert sarif["version"] == "2.1.0"
    run_block = sarif["runs"][0]
    driver = run_block["tool"]["driver"]
    assert driver["name"] == "Sawone Red"
    rule_ids = [rule["id"] for rule in driver["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert len(run_block["results"]) == len(result.findings)
    for item in run_block["results"]:
        assert item["ruleId"] in rule_ids
        assert item["level"] in ("error", "warning", "note")
        location = item["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"]


def test_html_report_is_branded_and_escapes_probe_content(write_config):
    html = render_html(_vulnerable_run(write_config))
    assert "SAWONE RED" in html
    assert "Copyright (c) 2026 Sawan Bhan" in html
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_json_summary_matches_findings(write_config):
    result = _vulnerable_run(write_config)
    payload = json.loads(to_json(result))
    assert payload["summary"]["findings"] == len(result.findings)
    assert payload["tool"]["name"] == "Sawone Red"


def test_write_reports_creates_every_requested_format(write_config, tmp_path):
    result = _vulnerable_run(write_config)
    written = write_reports(result, str(tmp_path / "out"), ("html", "json", "markdown", "sarif"))
    assert set(written) == {"html", "json", "markdown", "sarif"}
    for path in written.values():
        assert (tmp_path / "out").exists()
        assert open(path, encoding="utf-8").read().strip()
