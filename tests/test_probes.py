# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
import pytest

from sawone_red.errors import ConfigError
from sawone_red.owasp import OWASP_LLM_TOP10
from sawone_red.probes import load_packs, make_marker, parse_pack, render_prompt, select_probes

REQUIRED_PACKS = {
    "llm01-prompt-injection",
    "jailbreak-framings",
    "llm02-disclosure",
    "pii-handling",
    "llm05-output-handling",
    "llm06-excessive-agency",
    "agentic-tools",
}


def test_builtin_library_loads_and_covers_required_packs():
    packs = load_packs()
    assert REQUIRED_PACKS <= {pack.name for pack in packs}
    assert sum(len(pack.probes) for pack in packs) >= 20


def test_every_probe_has_known_owasp_category_and_remediation():
    for pack in load_packs():
        for probe in pack.probes:
            assert probe.owasp in OWASP_LLM_TOP10
            assert probe.remediation.strip()


def test_marker_is_deterministic_per_seed_and_probe():
    assert make_marker("seed", "A-1") == make_marker("seed", "A-1")
    assert make_marker("seed", "A-1") != make_marker("seed", "A-2")
    assert make_marker("seed", "A-1").startswith("SRMARK-")


def test_render_prompt_substitutes_placeholders():
    text = render_prompt("say {{MARKER}} and {{CANARY}}", "SRMARK-00000001", "SRCANARY-X")
    assert text == "say SRMARK-00000001 and SRCANARY-X"


def test_invalid_probe_reports_every_problem_with_its_id():
    bad = {
        "pack": "bad-pack",
        "title": "Bad",
        "owasp": "LLM01",
        "remediation": "fix it",
        "probes": [
            {
                "id": "BAD-1",
                "name": "x",
                "severity": "extreme",
                "prompt": "hi {{SECRET}}",
                "detector": {"type": "nope"},
            }
        ],
    }
    with pytest.raises(ConfigError) as exc:
        parse_pack(bad, "inline")
    message = str(exc.value)
    assert "BAD-1" in message
    assert "severity" in message
    assert "placeholders" in message
    assert "detector" in message


def test_unknown_pack_selection_is_rejected():
    with pytest.raises(ConfigError, match="unknown probe packs"):
        select_probes(load_packs(), ["does-not-exist"])
