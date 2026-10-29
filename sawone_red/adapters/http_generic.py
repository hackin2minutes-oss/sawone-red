# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Generic JSON-over-HTTP adapter for chatbot and agent endpoints.

The request body is a template: any string containing {{PROMPT}} is replaced
with the probe prompt. The reply text is read from a dotted JSON path such as
"data.reply" or "choices.0.text". Leave response_path empty to use the raw body.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from ..errors import AdapterError
from ._http import send_request

PROMPT_PLACEHOLDER = "{{PROMPT}}"


class HttpGenericAdapter:
    name = "http"

    def __init__(
        self,
        *,
        url: str,
        method: str = "POST",
        body: Any = None,
        headers: dict | None = None,
        response_path: str | None = None,
        auth_env: str | None = None,
        auth_header: str = "Authorization",
        auth_prefix: str = "Bearer ",
        timeout: float = 60.0,
    ) -> None:
        self.url = url
        self.method = method.upper()
        self.body = body if body is not None else {"prompt": PROMPT_PLACEHOLDER}
        self.headers = dict(headers or {})
        self.response_path = response_path
        self.auth_env = auth_env
        self.auth_header = auth_header
        self.auth_prefix = auth_prefix
        self.timeout = timeout

    def send(self, prompt: str) -> str:
        headers = {"Content-Type": "application/json", **self.headers}
        if self.auth_env:
            token = os.environ.get(self.auth_env)
            if not token:
                raise AdapterError(f"environment variable {self.auth_env} is not set")
            headers[self.auth_header] = self.auth_prefix + token
        payload = None
        if self.method != "GET":
            payload = json.dumps(_fill(self.body, prompt)).encode("utf-8")
        request = urllib.request.Request(self.url, data=payload, headers=headers, method=self.method)
        raw = send_request(request, self.timeout)
        if not self.response_path:
            return raw
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise AdapterError("target reply is not JSON but response_path is set") from exc
        value = _walk(data, self.response_path)
        if not isinstance(value, str):
            raise AdapterError(f"response_path {self.response_path!r} did not yield text")
        return value


def _fill(template: Any, prompt: str) -> Any:
    if isinstance(template, str):
        return template.replace(PROMPT_PLACEHOLDER, prompt)
    if isinstance(template, dict):
        return {key: _fill(value, prompt) for key, value in template.items()}
    if isinstance(template, list):
        return [_fill(value, prompt) for value in template]
    return template


def _walk(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise AdapterError(f"response_path {path!r} not found in the reply")
    return current
