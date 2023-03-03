#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""CMD_PARSE CLI command entry point."""
from suit_generator.envelope import SuitEnvelope


def main(input_file: str, output_file: str, output_format: str) -> None:
    """Parse input file.

    :param input_file: input file path
    :param output_file: output file path
    :param output_format: output file format

    """
    envelope = SuitEnvelope()
    envelope.load(input_file, "suit")
    envelope.dump(output_file, output_format)
