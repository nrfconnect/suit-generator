#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""CMD_PARSE CLI command entry point."""
from suit_generator.envelope import SuitEnvelope

PARSE_CMD = "parse"


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_parse_arg_parser = parser.add_parser(PARSE_CMD, help="Parse SUIT envelope.")
    cmd_parse_arg_parser.add_argument("--input-file", required=True, help="Input SUIT file.")
    cmd_parse_arg_parser.add_argument(
        "--output-file", required=False, help="Output file, yaml printed to STDOUT if not provided."
    )
    cmd_parse_arg_parser.add_argument(
        "--output-format",
        default="AUTO",
        choices=["json", "yaml", "AUTO"],
        help="Type of output file, types are recognized by extension (.yaml, .json). "
        "Use this parameter if file extension does not match.",
    )


def main(input_file: str, output_file: str, output_format: str) -> None:
    """Parse input file.

    :param input_file: input file path
    :param output_file: output file path
    :param output_format: output file format

    """
    envelope = SuitEnvelope()
    envelope.load(input_file, "suit")
    envelope.dump(output_file, output_format)
