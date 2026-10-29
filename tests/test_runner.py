# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
from sawone_red.config import load_config
from sawone_red.errors import AdapterError
from sawone_red.runner import run


def _mock_config(write_config, mode, outbound):
    text = f"""
target:
  type: mock
  mode: {mode}
canary: "SRCANARY-7A3F9B21C0DE4E55"
seed: "test-seed"
agent:
  private_data: true
  untrusted_input: true
  outbound_channel: {outbound}
"""
    return load_config(write_config(text))


def test_vulnerable_mock_yields_findings_across_packs(write_config):
    result = run(_mock_config(write_config, "vulnerable", "true"))
    ids = {finding.probe_id for finding in result.findings}
    assert len(result.findings) >= 20
    assert "AGENT-TRIFECTA" in ids
    assert {"LLM01-001", "LLM02-001", "LLM05-001", "LLM06-001", "PII-001", "AGT-001"} <= ids


def test_hardened_mock_yields_no_findings(write_config):
    result = run(_mock_config(write_config, "hardened", "false"))
    assert result.findings == []
    assert result.passed >= 20
    assert result.rating == "None"


def test_canary_probes_are_skipped_without_a_canary(write_config):
    config = load_config(write_config("target:\n  type: mock\nseed: x\n"))
    result = run(config)
    skipped = [r for r in result.results if r.status == "skipped"]
    assert skipped
    assert all("canary" in r.evidence for r in skipped)


class _Unreachable:
    def send(self, prompt):
        raise AdapterError("target unreachable")


def test_unreachable_target_is_reported_as_error_not_pass(write_config):
    config = load_config(
        write_config(
            "target:\n  type: http\n  url: https://staging.example.com/x\n"
            "authorization:\n  authorized: true\n  owner: Sawan Bhan\n  scope: staging\n"
            "canary: SRCANARY-1\n"
        )
    )
    result = run(config, adapter=_Unreachable())
    assert result.executed == 0
    assert result.findings == []
    assert result.errors == len(result.results)
