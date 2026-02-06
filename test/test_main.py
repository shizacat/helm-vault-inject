import re
from unittest.mock import MagicMock

import pytest

import hvac.exceptions
from src.vault_injector import (
    HVWrongPath,
    KVVersion,
    VaultInjector,
)


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


# ===== _split_path =====

@pytest.mark.parametrize(
    "path_input,expected",
    [
        ("/test/test..path/service.filename..pub", ("/test/test.path/service", "filename.pub", None)),
        ("/test/test..path/service.filename..pub.1", ("/test/test.path/service", "filename.pub", 1)),
        ("/check/service.key", ("/check/service", "key", None)),
        ("/check/service.key.04", ("/check/service", "key", 4)),
    ],
)
def test__split_path_ok(vault_injector: VaultInjector, path_input: str, expected):
    """_split_path returns (path, key, version) for valid paths."""
    assert vault_injector._split_path(path_input) == expected


@pytest.mark.parametrize(
    "path_input",
    [
        "/check",
        "/check.",
        "/check.key.key2",
        "/check.key.4.any",
        "/check.key.4.7",
    ],
)
def test__split_path_bad(vault_injector: VaultInjector, path_input: str):
    """_split_path raises ValueError for invalid path format."""
    with pytest.raises(ValueError):
        vault_injector._split_path(path_input)


# ===== _extract_path_from_str =====

@pytest.mark.parametrize(
    "template_str,expected_path",
    [
        ("VAULT:service_name/data.postgresql_url", "service_name/data.postgresql_url"),
        ("VAULT:secret/data.api_key", "secret/data.api_key"),
        ("VAULT:test/data.key", "test/data.key"),
    ],
)
def test__extract_path_from_str_ok(vault_injector: VaultInjector, template_str: str, expected_path: str):
    """_extract_path_from_str extracts path from VAULT: template string."""
    assert vault_injector._extract_path_from_str(template_str) == expected_path


def test__extract_path_from_str_with_environment(vault_injector: VaultInjector):
    """_extract_path_from_str replaces {environment} with config environment."""
    vault_injector.envs.environment = "/prod"
    assert vault_injector._extract_path_from_str("VAULT:app/{environment}/db.password") == "app/prod/db.password"


@pytest.mark.parametrize(
    "value,match",
    [
        ("", "path is empty"),
        ("VAULT:", "Empty secret template"),
        ("OTHER:secret/data.key", "path is wrong"),
    ],
)
def test__extract_path_from_str_bad(vault_injector: VaultInjector, value: str, match: str):
    """_extract_path_from_str raises ValueError for invalid input."""
    with pytest.raises(ValueError, match=match):
        vault_injector._extract_path_from_str(value)


# ===== _vault_read_by_path (mocked API) =====

def test__vault_read_by_path_kv1(vault_injector: VaultInjector):
    """KV v1: _vault_read_by_path uses client.read and returns key from data."""
    vault_injector.envs.kvversion = KVVersion.v1
    vault_injector.vault_client.read = MagicMock(return_value={"data": {"mykey": "secret-value"}})
    result = vault_injector._vault_read_by_path("/secret/mypath.mykey")
    assert result == "secret-value"
    vault_injector.vault_client.read.assert_called_once_with("/secret/mypath")


def test__vault_read_by_path_kv2(vault_injector: VaultInjector):
    """KV v2: _vault_read_by_path uses read_secret_version and returns key from data.data."""
    vault_injector.envs.kvversion = KVVersion.v2
    vault_injector.vault_client.secrets.kv.v2.read_secret_version = MagicMock(
        return_value={"data": {"data": {"mykey": "secret-value-v2"}}}
    )
    result = vault_injector._vault_read_by_path("/secret/mypath.mykey")
    assert result == "secret-value-v2"
    vault_injector.vault_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path="/secret/mypath",
        mount_point=vault_injector.envs.mount_point,
        raise_on_deleted_version=True,
        version=None,
    )


def test__vault_read_by_path_kv2_with_version(vault_injector: VaultInjector):
    """KV v2: _vault_read_by_path passes version to read_secret_version."""
    vault_injector.envs.kvversion = KVVersion.v2
    vault_injector.vault_client.secrets.kv.v2.read_secret_version = MagicMock(
        return_value={"data": {"data": {"user": "user-version-1"}}}
    )
    result = vault_injector._vault_read_by_path("/secret/testdata.user.1")
    assert result == "user-version-1"
    vault_injector.vault_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path="/secret/testdata",
        mount_point=vault_injector.envs.mount_point,
        raise_on_deleted_version=True,
        version=1,
    )


def test__vault_read_by_path_kv1_version_raises(vault_injector: VaultInjector):
    """KV v1: _vault_read_by_path raises RuntimeError when version is specified."""
    vault_injector.envs.kvversion = KVVersion.v1
    with pytest.raises(RuntimeError, match="KV version 1 don't get key by version"):
        vault_injector._vault_read_by_path("/secret/path.key.1")


def test__vault_read_by_path_invalid_path(vault_injector: VaultInjector):
    """_vault_read_by_path raises HVWrongPath when Vault returns InvalidPath."""
    vault_injector.envs.kvversion = KVVersion.v2
    vault_injector.vault_client.secrets.kv.v2.read_secret_version = MagicMock(
        side_effect=hvac.exceptions.InvalidPath("no such path")
    )
    with pytest.raises(HVWrongPath, match="Wrong path"):
        vault_injector._vault_read_by_path("/secret/nonexistent.key")


def test__vault_read_by_path_attribute_error(vault_injector: VaultInjector):
    """_vault_read_by_path raises RuntimeError on AttributeError (client misconfigured)."""
    vault_injector.envs.kvversion = KVVersion.v2
    vault_injector.vault_client.secrets.kv.v2.read_secret_version = MagicMock(
        side_effect=AttributeError("'NoneType' has no attribute 'kv'")
    )
    with pytest.raises(RuntimeError, match="Vault not configured correctly"):
        vault_injector._vault_read_by_path("/secret/path.key")


def test__get_int_ok(vault_injector: VaultInjector):
    """_get_int returns int for valid string."""
    assert vault_injector._get_int("42") == 42
    assert vault_injector._get_int("04", "Version") == 4


def test__get_int_bad(vault_injector: VaultInjector):
    """_get_int raises ValueError for non-int string."""
    with pytest.raises(ValueError, match="Version is not int"):
        vault_injector._get_int("abc", "Version")
