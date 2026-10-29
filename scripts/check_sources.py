# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Watch upstream OWASP sources for commits newer than the last human review.

Reads sources.yaml, asks each git remote for its current head commit, and
reports every source whose head differs from its reviewed commit. This script
never edits the probe library. A person reads the upstream diff, updates the
affected probes, and then records the new commit in sources.yaml.

Exit codes: 0 all sources match their reviewed commit, 1 at least one source
needs review, 2 a remote could not be read.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_KEYS = ("name", "url", "ref", "link", "reviewed")


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    ref: str
    link: str
    reviewed: str


def load_sources(path: Path) -> list[Source]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = data.get("sources")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path}: 'sources' must be a non-empty list")
    sources = []
    for entry in entries:
        missing = [key for key in REQUIRED_KEYS if key not in entry]
        if missing:
            raise ValueError(f"{path}: source {entry.get('name', '?')!r} is missing {', '.join(missing)}")
        reviewed = str(entry["reviewed"] or "")
        if reviewed and not SHA_RE.match(reviewed):
            raise ValueError(f"{path}: source {entry['name']!r} has an invalid reviewed commit")
        sources.append(Source(**{key: str(entry[key]) if key != "reviewed" else reviewed for key in REQUIRED_KEYS}))
    return sources


def remote_head(url: str, ref: str) -> str:
    output = subprocess.run(
        ["git", "ls-remote", url, ref],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout
    for line in output.splitlines():
        sha, _, name = line.partition("\t")
        if name == ref:
            return sha
    raise RuntimeError(f"ref {ref} not found at {url}")


def find_changes(sources: list[Source], heads: dict[str, str]) -> list[tuple[Source, str]]:
    """Return (source, upstream head) for every source that needs review."""
    return [(source, heads[source.name]) for source in sources if heads[source.name] != source.reviewed]


def build_report(pending: list[tuple[Source, str]]) -> str:
    lines = [
        "Upstream OWASP sources have changed since the probe library was last reviewed.",
        "",
        "| Source | Reviewed | Upstream head | Link |",
        "| --- | --- | --- | --- |",
    ]
    for source, head in pending:
        reviewed = source.reviewed[:10] or "never"
        lines.append(f"| {source.name} | {reviewed} | {head[:10]} | {source.link} |")
    lines += [
        "",
        "Review steps:",
        "",
        "1. Read the upstream changes at the links above.",
        "2. Update or add probes under `sawone_red/data/probes/`, and the OWASP mapping if categories moved.",
        "3. Run `pytest -q` and `sawone-red validate --config examples/mock.yaml`.",
        "4. Set `reviewed` for each source in `sources.yaml` to the upstream head shown above.",
        "5. Open a pull request. Closing this issue after merge is enough to stop reminders.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check OWASP sources against their reviewed commits.")
    parser.add_argument("--manifest", default="sources.yaml")
    parser.add_argument("--report", help="write a Markdown report to this path when changes are found")
    args = parser.parse_args(argv)

    try:
        sources = load_sources(Path(args.manifest))
        heads = {source.name: remote_head(source.url, source.ref) for source in sources}
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    pending = find_changes(sources, heads)
    if not pending:
        print("all upstream sources match their reviewed commits")
        return 0
    for source, head in pending:
        print(f"needs review: {source.name} reviewed={source.reviewed[:10] or 'never'} upstream={head[:10]}")
    if args.report:
        Path(args.report).write_text(build_report(pending), encoding="utf-8")
    return 1


if __name__ == "__main__":
    sys.exit(main())
