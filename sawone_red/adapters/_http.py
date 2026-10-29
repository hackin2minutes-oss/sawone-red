# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Shared HTTP plumbing for adapters (standard library only)."""

from __future__ import annotations

import urllib.error
import urllib.request

from ..errors import AdapterError


def send_request(request: urllib.request.Request, timeout: float) -> str:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise AdapterError(f"target returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise AdapterError(f"target unreachable: {exc.__class__.__name__}") from exc
