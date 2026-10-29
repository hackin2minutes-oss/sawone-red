# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Configuration loading and the authorization scope gate."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .errors import AuthorizationError, ConfigError
from .probes import SEVERITIES

TARGET_TYPES = ("mock", "openai", "http")
MOCK_MODES = ("vulnerable", "hardened")
REPORT_FORMATS = ("html", "json", "markdown", "sarif")
DEFAULT_FORMATS = ("html", "json", "markdown", "sarif")
AGENT_FLAGS = ("private_data", "untrusted_input", "outbound_channel")


@dataclass(frozen=True)
class Authorization:
    authorized: Any
    owner: Any
    scope: Any


@dataclass(frozen=True)
class AgentProfile:
    private_data: bool
    untrusted_input: bool
    outbound_channel: bool


@dataclass(frozen=True)
class Config:
    path: str
    name: str
    target: dict
    authorization: Authorization | None
    canary: str | None
    seed: str | None
    packs: Any
    probes_dir: str | None
    agent: AgentProfile | None
    fail_on: str
    output_dir: str
    formats: tuple[Any, ...]


def load_config(path: str) -> Config:
    file = Path(path)
    if not file.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: the config must be a YAML mapping")
    target = raw.get("target")
    if not isinstance(target, dict) or "type" not in target:
        raise ConfigError(f"{path}: 'target' must be a mapping with a 'type'")
    output = raw.get("output") or {}
    if not isinstance(output, dict):
        raise ConfigError(f"{path}: 'output' must be a mapping")
    return Config(
        path=path,
        name=str(raw.get("name") or file.stem),
        target=dict(target),
        authorization=_authorization(raw.get("authorization"), path),
        canary=_optional_str(raw, "canary", path),
        seed=None if raw.get("seed") is None else str(raw["seed"]),
        packs=raw.get("packs"),
        probes_dir=_optional_str(raw, "probes_dir", path),
        agent=_agent(raw.get("agent"), path),
        fail_on=str(raw.get("fail_on", "high")),
        output_dir=str(output.get("dir", "sawone-red-reports")),
        formats=tuple(output.get("formats", DEFAULT_FORMATS)),
    )


def validate_config(config: Config) -> list[str]:
    """Return every problem with the config. An empty list means it is well formed."""
    problems: list[str] = []
    kind = config.target.get("type")
    if kind not in TARGET_TYPES:
        problems.append(f"target.type must be one of {', '.join(TARGET_TYPES)}")
    elif kind == "mock":
        if config.target.get("mode", "vulnerable") not in MOCK_MODES:
            problems.append(f"mock target mode must be one of {', '.join(MOCK_MODES)}")
    elif kind == "openai":
        if not _nonempty(config.target.get("model")):
            problems.append("openai target needs 'model'")
        if not _nonempty(config.target.get("base_url")) and not _nonempty(config.target.get("url")):
            problems.append("openai target needs 'base_url' or 'url'")
    elif kind == "http":
        if not _nonempty(config.target.get("url")):
            problems.append("http target needs 'url'")
    if config.fail_on not in SEVERITIES:
        problems.append(f"fail_on must be one of {', '.join(SEVERITIES)}")
    if not config.formats or any(f not in REPORT_FORMATS for f in config.formats):
        problems.append(f"output.formats must be a non-empty list drawn from {', '.join(REPORT_FORMATS)}")
    if config.packs is not None and (
        not isinstance(config.packs, list) or not config.packs or not all(isinstance(p, str) for p in config.packs)
    ):
        problems.append("'packs' must be a non-empty list of pack names when set")
    if config.canary is not None and not config.canary.strip():
        problems.append("'canary' must not be blank")
    return problems


AUTHORIZATION_HINT = "add an authorization block with authorized: true, an owner and a scope"


def enforce_authorization(config: Config) -> None:
    """Refuse to test any real target unless the config asserts authorization.

    The built-in mock is self-contained and exempt. Everything else must carry
    authorized: true (the boolean), a non-blank owner and a non-blank scope.
    """
    kind = config.target.get("type")
    if kind == "mock":
        return
    auth = config.authorization
    if auth is None:
        raise AuthorizationError(f"target type {kind!r} is a real system; {AUTHORIZATION_HINT}")
    if auth.authorized is not True:
        raise AuthorizationError("authorization.authorized must be the boolean true (unquoted)")
    if not _nonempty(auth.owner):
        raise AuthorizationError("authorization.owner must name who authorized this test")
    if not _nonempty(auth.scope):
        raise AuthorizationError("authorization.scope must describe the systems covered")


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _optional_str(raw: dict, key: str, path: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{path}: '{key}' must be a string")
    return value


def _authorization(value: object, path: str) -> Authorization | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: 'authorization' must be a mapping")
    return Authorization(authorized=value.get("authorized"), owner=value.get("owner"), scope=value.get("scope"))


def _agent(value: object, path: str) -> AgentProfile | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: 'agent' must be a mapping")
    flags = {}
    for key in AGENT_FLAGS:
        flag = value.get(key, False)
        if not isinstance(flag, bool):
            raise ConfigError(f"{path}: agent.{key} must be true or false")
        flags[key] = flag
    return AgentProfile(**flags)
