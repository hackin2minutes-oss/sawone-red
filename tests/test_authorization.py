# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
import pytest

from sawone_red.cli import main
from sawone_red.config import enforce_authorization, load_config
from sawone_red.errors import AuthorizationError

HTTP_TARGET = "target:\n  type: http\n  url: https://staging.example.com/api/chat\n"


def test_real_target_without_authorization_is_refused(write_config):
    config = load_config(write_config(HTTP_TARGET))
    with pytest.raises(AuthorizationError, match="real system"):
        enforce_authorization(config)


@pytest.mark.parametrize("value", ["false", '"true"', "1", "no"])
def test_authorized_must_be_the_boolean_true(write_config, value):
    text = HTTP_TARGET + f"authorization:\n  authorized: {value}\n  owner: Sawan Bhan\n  scope: staging only\n"
    with pytest.raises(AuthorizationError, match="authorized"):
        enforce_authorization(load_config(write_config(text)))


@pytest.mark.parametrize("owner, scope", [('""', "staging only"), ("Sawan Bhan", '" "')])
def test_blank_owner_or_scope_is_refused(write_config, owner, scope):
    text = HTTP_TARGET + f"authorization:\n  authorized: true\n  owner: {owner}\n  scope: {scope}\n"
    with pytest.raises(AuthorizationError):
        enforce_authorization(load_config(write_config(text)))


def test_authorized_real_target_passes_the_gate(write_config):
    text = HTTP_TARGET + "authorization:\n  authorized: true\n  owner: Sawan Bhan\n  scope: staging chatbot only\n"
    enforce_authorization(load_config(write_config(text)))


def test_built_in_mock_is_exempt(write_config):
    enforce_authorization(load_config(write_config("target:\n  type: mock\n")))


def test_cli_refuses_unauthorized_target_and_writes_nothing(write_config, tmp_path):
    out = tmp_path / "reports"
    code = main(["run", "--config", write_config(HTTP_TARGET), "--output-dir", str(out)])
    assert code == 2
    assert not out.exists()
