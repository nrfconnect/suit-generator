#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""build_configuration module to create and parse build configuration."""

import re
import string


class BuildConfiguration(dict):
    """Represents a build system configuration, providing access to KConfig values.

    This class reads configuration data from a specified file and parses it.
    Configuration data is accessible as a dictionary.
    """

    config_value_pattern = re.compile(r"(?P<kconfig_name>[A-Za-z0-9_]+)=(?P<kconfig_value>.*)")

    def __init__(self, input_file: str = ".config") -> None:
        """Initialize a BuildConfiguration object."""
        super().__init__()
        try:
            with open(input_file, "r") as fh:
                self._config_data = fh.readlines()
        except FileNotFoundError as e:
            raise SystemExit(e)
        self._parse()

    def _parse(self) -> None:
        """Parse input .config file and populate the configuration dictionary."""
        for config_line in self._config_data:
            if re_result := self.config_value_pattern.match(config_line):
                kconfig_name = re_result.group("kconfig_name")
                kconfig_value = re_result.group("kconfig_value")
                if kconfig_value == "y":
                    # boolean value
                    kconfig_value = True
                elif kconfig_value.startswith("0x") and all(c in string.hexdigits for c in kconfig_value[2:]):
                    # hexadecimal value
                    kconfig_value = int(kconfig_value, base=16)
                elif kconfig_value.startswith('"') and kconfig_value.endswith('"'):
                    # string value
                    kconfig_value = kconfig_value[1:-1]
                elif kconfig_value.isdecimal():
                    # int value
                    kconfig_value = int(kconfig_value, base=10)
                super().__setitem__(kconfig_name, kconfig_value)
