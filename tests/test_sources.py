# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import check_sources  # noqa: E402

SHA_A = "a" * 40
SHA_B = "b" * 40


def _manifest(tmp_path, reviewed):
    path = tmp_path / "sources.yaml"
    path.write_text(
        "sources:\n"
        "  - name: demo\n"
        "    url: https://example.org/demo.git\n"
        "    ref: refs/heads/main\n"
        "    link: https://example.org/demo\n"
        f'    reviewed: "{reviewed}"\n',
        encoding="utf-8",
    )
    return path


def test_manifest_loads_and_the_repository_manifest_is_valid():
    sources = check_sources.load_sources(REPO_ROOT / "sources.yaml")
    assert {s.name for s in sources} >= {"owasp-llm-top10", "owasp-agentic-skills-top-10"}
    assert all(s.url.startswith("https://github.com/OWASP/") for s in sources)


def test_unreviewed_source_needs_review(tmp_path):
    sources = check_sources.load_sources(_manifest(tmp_path, ""))
    pending = check_sources.find_changes(sources, {"demo": SHA_A})
    assert [(s.name, head) for s, head in pending] == [("demo", SHA_A)]


def test_source_matching_its_reviewed_commit_is_current(tmp_path):
    sources = check_sources.load_sources(_manifest(tmp_path, SHA_A))
    assert check_sources.find_changes(sources, {"demo": SHA_A}) == []


def test_new_upstream_commit_needs_review(tmp_path):
    sources = check_sources.load_sources(_manifest(tmp_path, SHA_A))
    pending = check_sources.find_changes(sources, {"demo": SHA_B})
    assert len(pending) == 1
    assert "never" not in check_sources.build_report(pending)


def test_invalid_reviewed_commit_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="invalid reviewed commit"):
        check_sources.load_sources(_manifest(tmp_path, "not-a-sha"))


def test_missing_keys_are_reported(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("sources:\n  - name: demo\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing"):
        check_sources.load_sources(path)
