#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""CMD_CREATE CLI command entry point."""
from suit_generator.envelope import SuitEnvelope
from suit_generator.exceptions import SUITError
import logging

log = logging.getLogger(__name__)

CREATE_CMD = "create"


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_create_arg_parser = parser.add_parser(CREATE_CMD, help="Create SUIT envelope.")
    cmd_create_arg_parser.add_argument("--input-file", required=True, help="Input configuration file (yaml or json).")
    cmd_create_arg_parser.add_argument(
        "--input-format",
        default="AUTO",
        choices=["json", "yaml", "AUTO"],
        help="Type of input file, types are recognized by extension (.yaml, .json). "
        "Use this parameter if file extension does not match.",
    )
    cmd_create_arg_parser.add_argument("--output-file", required=True, help="Output SUIT file.")


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
