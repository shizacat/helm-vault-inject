#!/usr/bin/env python3

"""
Helm Vault Injector Plugin

This plugin place key from HashiCorp Vault into manifests rendered by Helm.

Logging is saved to vault_injector.log
"""

LOGGER_FILE_NAME = "./vault_injector.log"

import sys
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.addHandler(logging.FileHandler(LOGGER_FILE_NAME))

try:
    import hvac
    import hvac.exceptions
except ImportError as e:
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


class VaultInjector(object):
    """
    Helm Vault Injector Plugin class
    """

    def __init__(self, logger=None):
        self._logger = logger or logging.getLogger(__name__)

    def process(self, input_data: str) -> str:
        """
        Process Helm manifests and inject Vault keys.

        Args:
            input_data: Input YAML manifests from stdin

        Returns:
            Processed YAML manifests
        """
        return input_data


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
