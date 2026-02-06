import re
from unittest.mock import MagicMock

import pytest

from src.vault_injector import VaultInjector


# ===== Fixture ====

@pytest.fixture
def vault_injector() -> VaultInjector:
    obj = VaultInjector()
    obj.vault_client.is_authenticated = MagicMock(return_value=True)
    return obj


# ===== Tests =====

@pytest.mark.parametrize(
    "input_value,expected_calls,expected_result_type",
    [
        # String with single VAULT: — _replace_value is called, result is string
        (
            "url: VAULT:service_name/data.postgresql_url",
            ["VAULT:service_name/data.postgresql_url"],
            str,
        ),
        # String with single VAULT: and space after it
        (
            "url: VAULT:service_name/data.postgresql_url ",
            ["VAULT:service_name/data.postgresql_url"],
            str,
        ),
        # String with single VAULT: and space after it
        (
            "url: VAULT:service_name/data.postgresql_url",
            ["VAULT:service_name/data.postgresql_url"],
            str,
        ),
        # String with VAULT: at the start
        (
            "VAULT:secret/data.api_key",
            ["VAULT:secret/data.api_key"],
            str,
        ),
        # String with prefix (YAML key)
        (
            "random key: VAULT:test/data.key",
            ["VAULT:test/data.key"],
            str,
        ),
        # Empty string — no matches
        ("", [], str),
        # No VAULT: — no replacements, string returned as-is
        ("plain value", [], str),
        # Whitespace only
        ("   ", [], str),
        # Non-string — _replace_value not called, value returned as-is
        (42, [], int),
        ([1, 2], [], list),
        ({"a": 1}, [], dict),
        (None, [], type(None)),
    ],
)
def test__process_yaml_variants(
    vault_injector: VaultInjector,
    input_value,
    expected_calls,
    expected_result_type,
):
    """Check _process_yaml on various types and string variants with VAULT:."""
    mock_replace = MagicMock(
        side_effect=lambda m: m.group(0) if hasattr(m, "group") else m
    )
    vault_injector._replace_value = mock_replace

    result = vault_injector._process_yaml(input_value)

    assert type(result) is expected_result_type
    if isinstance(input_value, str):
        assert mock_replace.call_count == len(expected_calls)
        if expected_calls:
            for i, expected in enumerate(expected_calls):
                assert mock_replace.call_args_list[i][0][0].group(0) == expected
        else:
            assert result == input_value
    else:
        # Don't change non-string types, _replace_value should not be called
        assert result is input_value
        mock_replace.assert_not_called()
