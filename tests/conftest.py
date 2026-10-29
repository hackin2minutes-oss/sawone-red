# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"


@pytest.fixture
def write_config(tmp_path):
    def _write(text, name="config.yaml"):
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    return _write
