#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""CMD_KEYS CLI command entry point."""


class KeyGenerator:
    """Key pair generator."""

    def create_key_pair(self, output_file: str, key_type: str):
        """Create a pair of keys with output_file used as prefix in the name."""
        pass


def main(output_file: str, key_type: str) -> None:
    """Create signing keys.

    :param output_file: input file path
    :param key_type: output file type

    """
    key_gen = KeyGenerator()
    key_gen.create_key_pair(output_file, key_type)
