# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Probe library loading, validation and prompt rendering.

Probes live in YAML packs under data/probes/ (or a custom directory). Adding a
probe means editing YAML only; no Python changes are needed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .detectors import validate_detector
from .errors import ConfigError
from .owasp import OWASP_LLM_TOP10

BUILTIN_PROBES_DIR = Path(__file__).parent / "data" / "probes"
SEVERITIES = ("info", "low", "medium", "high", "critical")
PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Z_]+)\s*\}\}")
ALLOWED_PLACEHOLDERS = frozenset({"MARKER", "CANARY"})
PACK_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@dataclass(frozen=True)
class Probe:
    id: str
    name: str
    pack: str
    owasp: str
    severity: str
    prompt: str
    detector: dict
    remediation: str

    @property
    def requires_canary(self) -> bool:
        return self.detector["type"] == "canary_leak" or "CANARY" in PLACEHOLDER_RE.findall(self.prompt)


@dataclass(frozen=True)
class Pack:
    name: str
    title: str
    owasp: str
    source: str
    probes: tuple[Probe, ...]


def parse_pack(data: object, source: str) -> Pack:
    """Validate one YAML pack and return it. Raises ConfigError listing every problem."""
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: a probe pack must be a YAML mapping")
    errors: list[str] = []

    name = data.get("pack")
    if not isinstance(name, str) or not PACK_NAME_RE.match(name):
        errors.append(f"{source}: 'pack' must be a lowercase slug such as llm01-prompt-injection")
    title = data.get("title")
    if not isinstance(title, str) or not title.strip():
        errors.append(f"{source}: 'title' must be a non-empty string")
    pack_owasp = data.get("owasp")
    if pack_owasp not in OWASP_LLM_TOP10:
        errors.append(f"{source}: 'owasp' must be one of {', '.join(OWASP_LLM_TOP10)}")
    pack_remediation = data.get("remediation")
    if pack_remediation is not None and (not isinstance(pack_remediation, str) or not pack_remediation.strip()):
        errors.append(f"{source}: 'remediation' must be a non-empty string when set")

    raw_probes = data.get("probes")
    if not isinstance(raw_probes, list) or not raw_probes:
        errors.append(f"{source}: 'probes' must be a non-empty list")
        raw_probes = []

    probes: list[Probe] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_probes, start=1):
        if not isinstance(raw, dict):
            errors.append(f"{source}: probe #{index} must be a mapping")
            continue
        probe_id = raw.get("id")
        if not isinstance(probe_id, str) or not probe_id.strip():
            errors.append(f"{source}: probe #{index} needs a non-empty 'id'")
            continue
        label = f"{source}: probe {probe_id}"
        if probe_id in seen_ids:
            errors.append(f"{label} is duplicated inside this pack")
        seen_ids.add(probe_id)

        missing = [key for key in ("name", "severity", "prompt", "detector") if key not in raw]
        if missing:
            errors.append(f"{label} is missing {', '.join(missing)}")
            continue
        if raw["severity"] not in SEVERITIES:
            errors.append(f"{label}: severity must be one of {', '.join(SEVERITIES)}")
        prompt = raw["prompt"]
        if not isinstance(prompt, str) or not prompt.strip():
            errors.append(f"{label}: 'prompt' must be a non-empty string")
            prompt = ""
        else:
            unknown = set(PLACEHOLDER_RE.findall(prompt)) - ALLOWED_PLACEHOLDERS
            if unknown:
                errors.append(f"{label}: unknown placeholders {sorted(unknown)}")
        errors.extend(validate_detector(raw["detector"], label))
        probe_owasp = raw.get("owasp", pack_owasp)
        if probe_owasp not in OWASP_LLM_TOP10:
            errors.append(f"{label}: owasp must be one of {', '.join(OWASP_LLM_TOP10)}")
        remediation = raw.get("remediation", pack_remediation)
        if not isinstance(remediation, str) or not remediation.strip():
            errors.append(f"{label} needs a remediation on the probe or on the pack")

        probes.append(
            Probe(
                id=probe_id,
                name=str(raw["name"]),
                pack=str(name),
                owasp=str(probe_owasp),
                severity=str(raw["severity"]),
                prompt=prompt,
                detector=raw["detector"] if isinstance(raw["detector"], dict) else {},
                remediation=str(remediation or ""),
            )
        )

    if errors:
        raise ConfigError("\n".join(errors))
    return Pack(name=str(name), title=str(title), owasp=str(pack_owasp), source=source, probes=tuple(probes))


def load_packs(extra_dir: str | None = None) -> list[Pack]:
    """Load the built-in probe library plus an optional custom directory."""
    directories = [BUILTIN_PROBES_DIR]
    if extra_dir:
        directories.append(Path(extra_dir))
    packs: list[Pack] = []
    for directory in directories:
        if not directory.is_dir():
            raise ConfigError(f"probe directory not found: {directory}")
        for path in sorted(directory.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
            packs.append(parse_pack(data, str(path)))
    if not packs:
        raise ConfigError("no probe packs found")
    _check_unique(packs)
    return packs


def _check_unique(packs: list[Pack]) -> None:
    pack_names: set[str] = set()
    probe_ids: set[str] = set()
    errors: list[str] = []
    for pack in packs:
        if pack.name in pack_names:
            errors.append(f"duplicate pack name {pack.name!r} in {pack.source}")
        pack_names.add(pack.name)
        for probe in pack.probes:
            if probe.id in probe_ids:
                errors.append(f"duplicate probe id {probe.id!r} in {pack.source}")
            probe_ids.add(probe.id)
    if errors:
        raise ConfigError("\n".join(errors))


def select_probes(packs: list[Pack], names: list[str] | None) -> list[Probe]:
    """Return the probes of the named packs, or every probe when names is None."""
    if names is None:
        return [probe for pack in packs for probe in pack.probes]
    by_name = {pack.name: pack for pack in packs}
    unknown = [name for name in names if name not in by_name]
    if unknown:
        raise ConfigError(f"unknown probe packs: {', '.join(unknown)}")
    return [probe for name in names for probe in by_name[name].probes]


def make_marker(seed: str, probe_id: str) -> str:
    """Derive a per-probe marker. Same seed and probe give the same marker."""
    digest = hashlib.sha256(f"{seed}:{probe_id}".encode("utf-8")).hexdigest()[:8].upper()
    return f"SRMARK-{digest}"


def render_prompt(template: str, marker: str, canary: str | None) -> str:
    values = {"MARKER": marker, "CANARY": canary or ""}
    return PLACEHOLDER_RE.sub(lambda match: values[match.group(1)], template)
