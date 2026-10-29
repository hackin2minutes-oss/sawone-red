# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Adapter for OpenAI-compatible /chat/completions endpoints.

Works with OpenAI, Azure OpenAI (set 'url' to the full deployment URL), and
local servers such as vLLM or Ollama. The API key is read from the environment
variable named in the config and is never written to config or reports.
"""

from __future__ import annotations

import json
import os
import urllib.request

from ..errors import AdapterError, ConfigError
from ._http import send_request


class OpenAICompatAdapter:
    name = "openai"

    def __init__(
        self,
        *,
        base_url: str | None,
        url: str | None,
        model: str,
        api_key_env: str | None,
        system_prompt: str | None,
        canary: str | None,
        auth_header: str = "Authorization",
        auth_prefix: str = "Bearer ",
        timeout: float = 60.0,
    ) -> None:
        if not url and not base_url:
            raise ConfigError("openai target needs 'base_url' or 'url'")
        self.endpoint = url or base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.api_key_env = api_key_env
        self.system_prompt = (system_prompt or "").replace("{{CANARY}}", canary or "")
        self.auth_header = auth_header
        self.auth_prefix = auth_prefix
        self.timeout = timeout

    def send(self, prompt: str) -> str:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})
        body = json.dumps({"model": self.model, "messages": messages, "temperature": 0}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key_env:
            key = os.environ.get(self.api_key_env)
            if not key:
                raise AdapterError(f"environment variable {self.api_key_env} is not set")
            headers[self.auth_header] = self.auth_prefix + key
        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        raw = send_request(request, self.timeout)
        try:
            payload = json.loads(raw)
            return payload["choices"][0]["message"]["content"] or ""
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AdapterError("target reply does not match the chat completions shape") from exc
