#!/usr/bin/env python3

"""
Helm Vault Injector Plugin

This plugin place key from HashiCorp Vault into manifests rendered by Helm.

Logging is saved to vault_injector.log
"""

LOGGER_FILE_NAME = "./vault_injector.log"

import sys  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
from io import StringIO  # noqa: E402
from enum import Enum  # noqa: E402
from typing import Any, Optional, Tuple, Callable  # noqa: E402
from dataclasses import dataclass, fields  # noqa: E402

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.addHandler(logging.FileHandler(LOGGER_FILE_NAME))

try:
    import hvac
    import hvac.exceptions
except ImportError:
    logger.error(
        "The 'hvac' library is required. "
        "Please install it via 'pip install hvac'."
    )
    sys.exit(1)

try:
    import ruamel.yaml
except ImportError:
    logger.error(
        "The 'ruamel.yaml' library is required. "
        "Please install it via 'pip install ruamel.yaml'."
    )
    sys.exit(1)

if sys.version_info[:2] < (3, 7):
    raise Exception("Python 3.7 or a more recent version is required.")


# ---- Exceptions ----

class HelmVaultExcepion(Exception):
    """Base exception for HelmVault"""


class HVWrongPath(HelmVaultExcepion):
    """
    The path don't exist, or version in Vault
    """


# ----- Models -----

class KVVersion(Enum):
    v1 = "v1"
    v2 = "v2"

    def __str__(self):
        return self.value


@dataclass
class Config:
    mount_point: str = "secret"
    template: str = "VAULT:"
    deliminator: str = "changeme"
    kvversion: KVVersion = KVVersion.v2
    environment: str = ""

    @classmethod
    def create_from_env(
        cls,
        prefix: Optional[str] = ""
    ) -> "Config":
        kwargs = {}

        for f in fields(cls):
            env_name = f"{prefix}{f.name.upper()}"

            if env_name in os.environ:
                if f.name == "kvversion":
                    kvversion_str = os.environ[env_name]
                    kwargs[f.name] = (
                        KVVersion.v1 if kvversion_str == "v1" else KVVersion.v2
                    )
                else:
                    kwargs[f.name] = f.type(os.environ[env_name])

        return cls(**kwargs)

    def __post_init__(self):
        # add '/' before environment
        if self.environment and not self.environment.startswith("/"):
            self.environment = f"/{self.environment}"


class VaultInjector(object):
    """
    Helm Vault Injector Plugin class
    """
    SPLITER_KEY = "."
    CONFIG_ENV_PREFIX = "HELM_VAULT_"

    def __init__(self, logger=None):
        """
        Raises:
            RuntimeError
        """
        self._logger = logger or logging.getLogger(__name__)
        self.__current_walk_path = []

        # config from environment
        self.envs = Config.create_from_env(prefix=self.CONFIG_ENV_PREFIX)

        # yaml config
        self.yaml = ruamel.yaml.YAML()
        self.yaml.preserve_quotes = True
        # if you have very long string as multiline
        self.yaml.width = sys.maxsize

        # vault config
        self.vault_client = hvac.Client(
            namespace=os.environ.get("VAULT_NAMESPACE")
        )
        if not self.vault_client.is_authenticated():
            raise RuntimeError(
                "Vault not configured correctly, "
                "check VAULT_ADDR and VAULT_TOKEN env variables."
            )

    def process(self, yaml_string: str) -> str:
        """
        Process Helm manifests and inject Vault keys.

        Args:
            input_data: Input YAML manifests from stdin

        Returns:
            Processed YAML manifests
        """
        data = self._json_walker(
            self.yaml.load(yaml_string), self._process_yaml
        )
        # Convert YAML back to string
        output = StringIO()
        self.yaml.dump(data, output)
        return output.getvalue()

    def _json_walker(
        self, data, process: Callable[[Any], Any], is_root: bool = False
    ):
        """Walk through the loaded yaml file and call process

        Args
            data - json object

        Return
            new json object
        """
        if is_root:
            self.__current_walk_path = []

        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if is_root:
                    self.__current_walk_path = []
                self.__current_walk_path.append(key)
                result[key] = self._json_walker(value, process)
                self.__current_walk_path.pop()
            return result
        elif isinstance(data, list):
            result = []
            for item in data:
                result.append(self._json_walker(item, process))
            return result
        return process(data)

    def _process_yaml(self, value):
        """Process data"""
        path = self._check_value_template(value)
        if path is not None:
            return self._vault_read_by_path(path)
        return value

    def _check_value_template(self, value: str) -> Optional[str]:
        """Check value on template

        Return
            path
        """
        if not isinstance(value, str):
            return
        value = value.strip()

        if value.startswith(self.envs.template):
            value = value[len(self.envs.template):]
            if not value:
                raise ValueError("Empty secret template")
            value = value.replace("{environment}", self.envs.environment)
            return value.replace("//", "/")

    def _vault_read_by_path(self, path: str) -> str:
        """
        Take data from Vault by path and return it
        Analog vault read

        Raises
            RuntimeError
            HVWrongPath

        Return
            value for path
        """
        path, key, version = self._split_path(path)

        if self._logger:
            self._logger.info(f"Using KV Version: {self.envs.kvversion}")
            self._logger.info(
                "Attempting to read to url: {}/v1/{}/data{}".format(
                    self.vault_client.url, self.envs.mount_point, path
                ),
            )

        try:
            if self.envs.kvversion == KVVersion.v1:
                if version is not None:
                    raise RuntimeError(
                        "KV version 1 don't get key by version, "
                        f"path: {path}.{key}"
                    )
                data = self.vault_client.read(path)
                return data.get("data", {}).get(key)
            if self.envs.kvversion == KVVersion.v2:
                data = self.vault_client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=self.envs.mount_point,
                    raise_on_deleted_version=True,
                    version=version
                )
                return data.get("data", {}).get("data", {}).get(key)
            raise RuntimeError("Wrong KV Version specified, either v1 or v2")
        except AttributeError as ex:
            raise RuntimeError(
                "Vault not configured correctly,"
                f"check VAULT_ADDR and VAULT_TOKEN env variables. {ex}"
            )
        except hvac.exceptions.InvalidPath:
            raise HVWrongPath(f"Wrong path: {path}")

    def _split_path(self, path: str) -> Tuple[str, str, Optional[str]]:
        """
        Split path to Vault key/value using regex
        Format: "/path/a/b/c<SPLITER:.>key<SPLITER:.><version optional>"

        Split on single separator (double separators are skipped)

        Raises
            ValueError if path contains multiple dots or wrong format

        Return
            path, key, version - if specified
            where:
                key is name of field in Vault
                version is version of path
        """
        pattern = re.compile(
            rf'(.*?[^{re.escape(self.SPLITER_KEY)}])'
            rf'{re.escape(self.SPLITER_KEY)}'
            rf'([^{re.escape(self.SPLITER_KEY)}].*)$'
        )
        v_version: Optional[int] = None

        # Find path
        match = pattern.match(path)
        if not match:
            raise ValueError(f"Wrong format path: {path}")
        v_path = match.group(1)

        # Find key
        v_key = match.group(2)
        match = pattern.match(match.group(2))
        if match is not None:
            # have a third section
            v_key = match.group(1)
            v_version = self._get_int(match.group(2), "Version")

        v_path = v_path.replace(self.SPLITER_KEY * 2, self.SPLITER_KEY)
        v_key = v_key.replace(self.SPLITER_KEY * 2, self.SPLITER_KEY)
        return v_path, v_key, v_version

    def _get_int(self, value, note: Optional[str] = None) -> int:
        try:
            return int(value)
        except ValueError:
            raise ValueError(f'{"Value" if note is None else note} is not int')


def main():
    """
    Main function to read from stdin and write to stdout
    """
    try:
        vinj = VaultInjector(logger=logger)
    except Exception as e:
        sys.stderr.write(f"Error initializing VaultInjector: {e}\n")
        sys.exit(1)

    try:
        sys.stdout.write(vinj.process(sys.stdin.read()))
    except Exception as e:
        sys.stderr.write(f"Error processing input: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
