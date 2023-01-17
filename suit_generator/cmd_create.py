#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""CMD_CREATE CLI command entry point."""
from suit_generator.envelope import SuitEnvelope
from suit_generator.logger import log_call
import logging

log = logging.getLogger(__name__)


@log_call
def main(input_file: str, input_format: str, output_file: str, start_point: str) -> None:
    """Create SUIT envelope.

    :param input_file: input file path
    :param input_format: input file format (json, yaml)
    :param output_file: output file path
    :param start_point: from which element output CBOR shall be created, i.e. generation of command sequence only

    """
    envelope = SuitEnvelope()
    envelope.load(input_file, input_format)
    envelope.dump(output_file, "suit")
