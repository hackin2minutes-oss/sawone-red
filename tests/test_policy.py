# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Repository policy: ownership headers, plain ASCII text, no third-party red-team frameworks."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
SKIP_DIRS = {".git", ".venv", ".pytest_cache", "__pycache__", "build", "dist", "sawone_red.egg-info", "sawone-red-reports"}
HEADER = "Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License."
HEADER_SUFFIXES = {".py", ".yaml", ".yml", ".sh", ".toml"}
TEXT_SUFFIXES = HEADER_SUFFIXES | {".md"}
TEXT_NAMES = {"Dockerfile", "LICENSE", ".gitignore"}
FORBIDDEN = ("co-authored-by", "generated with", "claude", "anthropic", "promptfoo", "garak", "pyrit", "deepteam")


def _text_files():
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES:
            files.append(path)
    return sorted(files)


def _label(path):
    return str(path.relative_to(ROOT))


@pytest.mark.parametrize("path", _text_files(), ids=_label)
def test_text_is_plain_ascii(path):
    assert path.read_text(encoding="utf-8").isascii(), f"{_label(path)} has non-ASCII characters"


@pytest.mark.parametrize(
    "path",
    [p for p in _text_files() if p.suffix in HEADER_SUFFIXES or p.name == "Dockerfile"],
    ids=_label,
)
def test_source_files_carry_the_ownership_header(path):
    head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:5])
    assert HEADER in head, f"{_label(path)} is missing the copyright header"


@pytest.mark.parametrize("path", [p for p in _text_files() if p.resolve() != SELF], ids=_label)
def test_no_ai_authorship_traces_or_forbidden_frameworks(path):
    lowered = path.read_text(encoding="utf-8").lower()
    for term in FORBIDDEN:
        assert term not in lowered, f"{_label(path)} contains {term!r}"
