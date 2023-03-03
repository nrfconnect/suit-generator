#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""CMD_CREATE CLI command entry point."""
from suit_generator.envelope import SuitEnvelope
from suit_generator.exceptions import SUITError
import logging

log = logging.getLogger(__name__)


def main(input_file: str, input_format: str, output_file: str) -> None:
    """Create SUIT envelope.

    :param input_file: input file path
    :param input_format: input file format (json, yaml)
    :param output_file: output file path

    """
    try:
        envelope = SuitEnvelope()
        envelope.load(input_file, input_format)
        envelope.dump(output_file, "suit")
    except ValueError as error:
        raise SUITError(f"Invalid value: {error}") from error
    except FileNotFoundError as error:
        raise SUITError(f"Invalid path: {error}") from error
