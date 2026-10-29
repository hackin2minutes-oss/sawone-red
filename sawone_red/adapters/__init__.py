# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Target adapters: each takes a prompt and returns the target's reply text."""

from __future__ import annotations

from typing import Protocol

from ..errors import ConfigError
from .http_generic import HttpGenericAdapter
from .mock import MockTarget
from .openai_compat import OpenAICompatAdapter


class Adapter(Protocol):
    def send(self, prompt: str) -> str: ...


def build_adapter(target: dict, canary: str | None) -> Adapter:
    kind = target.get("type")
    if kind == "mock":
        return MockTarget(mode=target.get("mode", "vulnerable"), canary=canary)
    if kind == "openai":
        return OpenAICompatAdapter(
            base_url=target.get("base_url"),
            url=target.get("url"),
            model=target["model"],
            api_key_env=target.get("api_key_env"),
            system_prompt=target.get("system_prompt"),
            canary=canary,
            auth_header=target.get("auth_header", "Authorization"),
            auth_prefix=target.get("auth_prefix", "Bearer "),
            timeout=float(target.get("timeout", 60)),
        )
    if kind == "http":
        return HttpGenericAdapter(
            url=target["url"],
            method=target.get("method", "POST"),
            body=target.get("body"),
            headers=target.get("headers"),
            response_path=target.get("response_path"),
            auth_env=target.get("auth_env"),
            auth_header=target.get("auth_header", "Authorization"),
            auth_prefix=target.get("auth_prefix", "Bearer "),
            timeout=float(target.get("timeout", 60)),
        )
    raise ConfigError(f"unsupported target type {kind!r}")


def describe_target(target: dict) -> str:
    """A human-readable label for reports. Never includes credentials."""
    kind = target.get("type")
    if kind == "mock":
        return f"built-in mock ({target.get('mode', 'vulnerable')} mode)"
    if kind == "openai":
        return f"{target.get('base_url') or target.get('url')} model={target.get('model')}"
    if kind == "http":
        return f"{target.get('url')} (generic HTTP)"
    return str(kind)
