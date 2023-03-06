#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#

"""Implementation of CLI argument parser."""

from argparse import ArgumentParser
from typing import Tuple

from suit_generator.cmd_keys import KeyGenerator

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
        choices=["json", "yaml", "AUTO"],
        help="Type of input file, types are recognized by extension (.yaml, .json). "
        "Use this parameter if file extension does not match.",
    )
    cmd_create_arg_parser.add_argument("--output-file", required=True, help="Output SUIT file.")
    # PARSE_CMD command
    cmd_parse_arg_parser = subparsers.add_parser(PARSE_CMD, help="Parse SUIT envelope.")
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
    # KEYS_CMD command
    cmd_keys_arg_parser = subparsers.add_parser(KEYS_CMD, help="Create pair of signing keys.")
    cmd_keys_arg_parser.add_argument("--output-file", required=True, help="Prefix for output files.")
    cmd_keys_arg_parser.add_argument(
        "--type",
        required=False,
        default=KeyGenerator.default_key_type,
        help=f"Output key file type. Default: {KeyGenerator.default_key_type}",
        choices=KeyGenerator.supported_key_types.keys(),
    )
    cmd_keys_arg_parser.add_argument(
        "--encoding",
        required=False,
        default=KeyGenerator.default_encoding,
        help=f"Key encoding. Default: {KeyGenerator.default_encoding}",
        choices=KeyGenerator.supported_encodings.keys(),
    )
    cmd_keys_arg_parser.add_argument(
        "--private-format",
        required=False,
        default=KeyGenerator.default_private_format,
        help=f"Private key format. Default: {KeyGenerator.default_private_format}",
        choices=KeyGenerator.supported_private_formats.keys(),
    )
    cmd_keys_arg_parser.add_argument(
        "--public-format",
        required=False,
        default=KeyGenerator.default_public_format,
        help=f"Public key format. Default: {KeyGenerator.default_public_format}",
        choices=KeyGenerator.supported_public_formats.keys(),
    )
    cmd_keys_arg_parser.add_argument(
        "--encryption",
        required=False,
        default=KeyGenerator.default_encryption,
        help=f"Key encryption. Default: {KeyGenerator.default_encryption}",
        choices=KeyGenerator.supported_encryptions.keys(),
    )
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
