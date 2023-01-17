#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""CMD_KEYS CLI command entry point."""
from suit_generator.logger import log_call


class KeyGenerator:
    """Key pair generator."""

    def create_key_pair(self, output_file: str, type: str):
        """Create a pair of keys with output_file used as prefix in the name."""
        pass


@log_call
def main(output_file: str, type: str) -> None:
    """Create signing keys.

    :param output_file: input file path
    :param type: output file type

    """
    key_gen = KeyGenerator()
    key_gen.create_key_pair(output_file, type)
