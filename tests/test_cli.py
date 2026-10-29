# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
from pathlib import Path

from sawone_red.cli import main

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_vulnerable_mock_fails_the_gate_and_writes_reports(tmp_path):
    sarif = tmp_path / "vulnerable.sarif"
    code = main(
        [
            "run",
            "--config",
            str(EXAMPLES / "mock.yaml"),
            "--output-dir",
            str(tmp_path / "vulnerable"),
            "--sarif",
            str(sarif),
        ]
    )
    assert code == 1
    assert (tmp_path / "vulnerable" / "report.html").is_file()
    assert (tmp_path / "vulnerable" / "results.json").is_file()
    assert (tmp_path / "vulnerable" / "report.md").is_file()
    assert sarif.is_file()


def test_hardened_mock_passes_the_gate(tmp_path):
    code = main(
        ["run", "--config", str(EXAMPLES / "mock-hardened.yaml"), "--output-dir", str(tmp_path)]
    )
    assert code == 0


def test_fail_on_critical_still_fails_on_vulnerable_mock(tmp_path):
    code = main(
        [
            "run",
            "--config",
            str(EXAMPLES / "mock.yaml"),
            "--fail-on",
            "critical",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 1


def test_validate_and_list_packs_succeed():
    assert main(["validate", "--config", str(EXAMPLES / "mock.yaml")]) == 0
    assert main(["list-packs"]) == 0


def test_validate_rejects_a_broken_config(write_config):
    assert main(["validate", "--config", write_config("target:\n  type: openai\n")]) == 2
