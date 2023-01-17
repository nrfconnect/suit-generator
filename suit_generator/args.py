#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#

"""Implementation of CLI argument parser."""

from argparse import ArgumentParser
from typing import Tuple

PARSE_CMD = "parse"
CREATE_CMD = "create"
KEYS_CMD = "keys"
SIGN_CMD = "sign"


def parse_arguments() -> Tuple:
    """
    Parse CLI parameters.

    Parse passed CLI parameters and return argparse.Namespace

    :return: Tuple contains command and it's parameters
    """
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True, help="Choose subcommand:")
    # CREATE_CMD command
    cmd_create_arg_parser = subparsers.add_parser(CREATE_CMD, help="Create SUIT envelope.")
    cmd_create_arg_parser.add_argument("--input-file", required=True, help="Input configuration file (yaml or json).")
    cmd_create_arg_parser.add_argument(
        "--input-format",
        default="AUTO",
        help="Type of input file, types are recognized by extension (.yaml, .json). "
        "Use this parameter if file extension does not match.",
    )
    cmd_create_arg_parser.add_argument("--output-file", required=True, help="Output SUIT file.")
    cmd_create_arg_parser.add_argument(
        "--start-point",
        required=False,
        help="Definition from which element output CBOR shall be created, i.e. generation of command sequence only",
    )
    # PARSE_CMD command
    cmd_parse_arg_parser = subparsers.add_parser(PARSE_CMD, help="Parse SUIT envelope.")
    cmd_parse_arg_parser.add_argument("--input-file", required=True, help="Input SUIT file.")
    cmd_parse_arg_parser.add_argument(
        "--output-file", required=False, help="Output file, yaml printed to STDOUT if not provided."
    )
    cmd_parse_arg_parser.add_argument(
        "--output-format",
        default="AUTO",
        help="Type of output file, types are recognized by extension (.yaml, .json). "
        "Use this parameter if file extension does not match.",
    )
    # KEYS_CMD command
    cmd_keys_arg_parser = subparsers.add_parser(KEYS_CMD, help="Create pair of signing keys.")
    cmd_keys_arg_parser.add_argument("--output-file", required=True, help="Prefix for output files.")
    cmd_keys_arg_parser.add_argument("--type", required=True, default="secp256r1", help="Output file.")
    # SIGN_CMD command
    cmd_sign_arg_parser = subparsers.add_parser(SIGN_CMD, help="Sign manifest")
    cmd_sign_arg_parser.add_argument("--input-file", required=True, help="Input SUIT file")
    cmd_sign_arg_parser.add_argument("--output-file", required=True, help="Output SUIT file")
    cmd_sign_arg_parser.add_argument("--private-key", required=True, help="Private key file")

    arguments = parser.parse_args()
    cmd = str(arguments.command)
    # remove unnecessary arguments to simplify command calling
    del arguments.command

    return cmd, arguments
