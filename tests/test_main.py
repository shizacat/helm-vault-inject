import re
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

import hvac.exceptions
from src.vault_injector import (
    Config,
    HVWrongPath,
    KVVersion,
    VaultInjector,
    main,
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


# ===== _json_walker =====

def test__json_walker_scalar_calls_process(vault_injector: VaultInjector):
    """_json_walker on scalar calls process and returns its result."""
    process = MagicMock(side_effect=lambda x: f"processed_{x}")
    result = vault_injector._json_walker(42, process)
    assert result == "processed_42"
    process.assert_called_once_with(42)


def test__json_walker_string_calls_process(vault_injector: VaultInjector):
    """_json_walker on string calls process."""
    process = MagicMock(return_value="out")
    assert vault_injector._json_walker("hello", process) == "out"
    process.assert_called_once_with("hello")


def test__json_walker_list_processes_each_item(vault_injector: VaultInjector):
    """_json_walker on list returns new list with each element processed."""
    process = MagicMock(side_effect=lambda x: x * 2 if isinstance(x, int) else x)
    result = vault_injector._json_walker([1, 2, 3], process)
    assert result == [2, 4, 6]
    assert process.call_count == 3


def test__json_walker_dict_processes_each_value(vault_injector: VaultInjector):
    """_json_walker on dict returns new dict with each value processed."""
    process = MagicMock(side_effect=lambda x: x.upper() if isinstance(x, str) else x)
    data = {"a": "x", "b": "y"}
    result = vault_injector._json_walker(data, process)
    assert result == {"a": "X", "b": "Y"}
    assert process.call_count == 2


def test__json_walker_nested_dict_list(vault_injector: VaultInjector):
    """_json_walker recurses into nested dict and list."""
    process = MagicMock(side_effect=lambda x: x + 1 if isinstance(x, int) else x)
    data = {"k": [1, {"n": 2}]}
    result = vault_injector._json_walker(data, process)
    assert result == {"k": [2, {"n": 3}]}
    # call for value: 1 - as value, 2 as value in nested dict
    assert process.call_count == 2


def test__json_walker_empty_list(vault_injector: VaultInjector):
    """_json_walker on empty list returns empty list without calling process."""
    process = MagicMock()
    result = vault_injector._json_walker([], process)
    assert result == []
    process.assert_not_called()


def test__json_walker_empty_dict(vault_injector: VaultInjector):
    """_json_walker on empty dict returns empty dict without calling process."""
    process = MagicMock()
    result = vault_injector._json_walker({}, process)
    assert result == {}
    process.assert_not_called()


def test__json_walker_is_root_resets_path(vault_injector: VaultInjector):
    """_json_walker with is_root=True can be used twice without path leak."""
    process = MagicMock(return_value=1)
    data = {"a": 1}
    r1 = vault_injector._json_walker(data, process, is_root=True)
    r2 = vault_injector._json_walker(data, process, is_root=True)
    assert r1 == {"a": 1}
    assert r2 == {"a": 1}
    assert process.call_count == 2


def test__json_walker_with_process_yaml_integration(vault_injector: VaultInjector):
    """_json_walker with _process_yaml replaces VAULT: strings (mocked _replace_value)."""
    vault_injector._replace_value = MagicMock(
        side_effect=lambda m: "replaced_" + (m.group(0).replace("VAULT:", ""))
    )
    data = {"key": "VAULT:secret/data.foo", "other": "plain"}
    result = vault_injector._json_walker(data, vault_injector._process_yaml, is_root=True)
    assert result["key"].startswith("replaced_")
    assert result["other"] == "plain"


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

# ===== Config =====

def test_config_defaults():
    """Config has expected default values when created without kwargs."""
    cfg = Config()
    assert cfg.mount_point == "secret"
    assert cfg.template == "VAULT:"
    assert cfg.deliminator == "changeme"
    assert cfg.kvversion == KVVersion.v2
    assert cfg.environment == ""


def test_config_create_from_env_empty(monkeypatch):
    """create_from_env with no env vars returns config with defaults."""
    for key in ("MOUNT_POINT", "TEMPLATE", "DELIMINATOR", "KVVERSION", "ENVIRONMENT"):
        monkeypatch.delenv(key, raising=False)
    cfg = Config.create_from_env()
    assert cfg.mount_point == "secret"
    assert cfg.template == "VAULT:"
    assert cfg.deliminator == "changeme"
    assert cfg.kvversion == KVVersion.v2
    assert cfg.environment == ""


def test_config_create_from_env_string_fields(monkeypatch):
    """create_from_env reads MOUNT_POINT, TEMPLATE, DELIMINATOR from env."""
    monkeypatch.setenv("MOUNT_POINT", "my-mount")
    monkeypatch.setenv("TEMPLATE", "SECRET:")
    monkeypatch.setenv("DELIMINATOR", "mydelim")
    cfg = Config.create_from_env()
    assert cfg.mount_point == "my-mount"
    assert cfg.template == "SECRET:"
    assert cfg.deliminator == "mydelim"
    assert cfg.kvversion == KVVersion.v2
    assert cfg.environment == ""


def test_config_create_from_env_kvversion_v1(monkeypatch):
    """create_from_env sets kvversion to v1 when KVVERSION=v1."""
    monkeypatch.setenv("KVVERSION", "v1")
    cfg = Config.create_from_env()
    assert cfg.kvversion == KVVersion.v1


def test_config_create_from_env_kvversion_v2(monkeypatch):
    """create_from_env sets kvversion to v2 when KVVERSION=v2 or other value."""
    monkeypatch.setenv("KVVERSION", "v2")
    cfg = Config.create_from_env()
    assert cfg.kvversion == KVVersion.v2
    monkeypatch.setenv("KVVERSION", "v3")
    cfg2 = Config.create_from_env()
    assert cfg2.kvversion == KVVersion.v2


def test_config_create_from_env_with_prefix(monkeypatch):
    """create_from_env(prefix) uses prefixed env var names."""
    monkeypatch.setenv("HELM_VAULT_MOUNT_POINT", "prefixed-mount")
    monkeypatch.setenv("HELM_VAULT_TEMPLATE", "PREFIX:")
    cfg = Config.create_from_env(prefix="HELM_VAULT_")
    assert cfg.mount_point == "prefixed-mount"
    assert cfg.template == "PREFIX:"


def test_config_environment_adds_slash(monkeypatch):
    """Config __post_init__ adds leading '/' to environment if missing."""
    monkeypatch.setenv("ENVIRONMENT", "prod")
    cfg = Config.create_from_env()
    assert cfg.environment == "/prod"


def test_config_environment_keeps_slash(monkeypatch):
    """Config __post_init__ does not double slash when environment already starts with /."""
    monkeypatch.setenv("ENVIRONMENT", "/prod")
    cfg = Config.create_from_env()
    assert cfg.environment == "/prod"


def test_config_environment_empty_unchanged():
    """Config with empty environment leaves it empty."""
    cfg = Config(environment="")
    assert cfg.environment == ""


# ===== main =====

def test_main_success():
    """main reads from stdin, processes via VaultInjector, writes result to stdout."""
    stdin_input = "key: value\n"
    expected_output = "key: replaced\n"
    mock_vinj = MagicMock()
    mock_vinj.process.return_value = expected_output

    with patch("src.vault_injector.VaultInjector", return_value=mock_vinj):
        with patch("sys.stdin", StringIO(stdin_input)):
            with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
                main()

    mock_vinj.process.assert_called_once_with(stdin_input)
    assert mock_stdout.getvalue() == expected_output


def test_main_init_error():
    """main exits with code 1 when VaultInjector initialization fails."""
    with patch("src.vault_injector.VaultInjector", side_effect=RuntimeError("Vault unreachable")):
        with pytest.raises(SystemExit) as exc_info:
            main()
    assert exc_info.value.code == 1


def test_main_process_error():
    """main exits with code 1 when process() raises."""
    mock_vinj = MagicMock()
    mock_vinj.process.side_effect = ValueError("Invalid YAML")

    with patch("src.vault_injector.VaultInjector", return_value=mock_vinj):
        with patch("sys.stdin", StringIO("input")):
            with pytest.raises(SystemExit) as exc_info:
                main()
    assert exc_info.value.code == 1
