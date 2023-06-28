#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

"""Implementation of CLI argument parser."""

from argparse import ArgumentParser
from typing import Tuple

from suit_generator.cmd_keys import KeyGenerator
from suit_generator.cmd_convert import KeyConverter
from suit_generator.cmd_image import ImageCreator
from suit_generator.exceptions import GeneratorError

PARSE_CMD = "parse"
CREATE_CMD = "create"
KEYS_CMD = "keys"
CONVERT_CMD = "convert"
SIGN_CMD = "sign"
IMAGE_CMD = ImageCreator.IMAGE_CMD
IMAGE_CMD_BOOT = ImageCreator.IMAGE_CMD_BOOT
IMAGE_CMD_UPDATE = ImageCreator.IMAGE_CMD_UPDATE


def _parser() -> ArgumentParser:
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
    # CONVERT_CMD command
    cmd_convert_arg_parser = subparsers.add_parser(
        CONVERT_CMD, help="Convert private key file in PEM format into a C file storing public key data as an array."
    )
    cmd_convert_arg_parser.add_argument("--input-file", required=True, help="Private key file in PEM format.")
    cmd_convert_arg_parser.add_argument(
        "--output-file", required=True, help="C file to be created; will hold public key data as an array."
    )
    cmd_convert_arg_parser.add_argument(
        "--array-type",
        required=False,
        default=KeyConverter.default_array_type,
        help=f"C type to be used as a key contents array. Default: {KeyConverter.default_array_type}",
    )
    cmd_convert_arg_parser.add_argument(
        "--array-name",
        required=False,
        default=KeyConverter.default_array_name,
        help=f"Valid C variable name to be used for array containing the key. "
        f"Default: {KeyConverter.default_array_name}",
    )
    cmd_convert_arg_parser.add_argument(
        "--length-type",
        required=False,
        default=KeyConverter.default_length_type,
        help=f"C type to be used as an array length variable. Default: {KeyConverter.default_length_type}",
    )
    cmd_convert_arg_parser.add_argument(
        "--length-name",
        required=False,
        default=KeyConverter.default_length_name,
        help=f"Valid C variable name to be used for array length. Default: {KeyConverter.default_length_name}",
    )
    cmd_convert_arg_parser.add_argument(
        "--columns-count",
        required=False,
        type=int,
        default=KeyConverter.default_columns_count,
        help=f"Number of columns of C code of an array. Default: {KeyConverter.default_columns_count}",
    )
    cmd_convert_arg_parser.add_argument(
        "--header-file",
        required=False,
        default=KeyConverter.default_header_file,
        help=f"Use this file's contents as a generated C file header/banner, e.g. as a license, #ifdef guards, etc. "
        f"Default: {KeyConverter.default_header_file}",
    )
    cmd_convert_arg_parser.add_argument(
        "--footer-file",
        required=False,
        default=KeyConverter.default_footer_file,
        help=f"Use this file's contents as a generated C file footer, e.g. to close #ifdef guards. "
        f"Default: {KeyConverter.default_footer_file}",
    )
    cmd_convert_arg_parser.add_argument(
        "--indentation-count",
        required=False,
        default=KeyConverter.default_indentation_count,
        help=f"Number of indentation characters to put at the beginning of array lines. "
        f"Default: {KeyConverter.default_indentation_count}",
    )
    cmd_convert_arg_parser.add_argument(
        "--indentation-tab",
        required=False,
        action="store_true",
        help="Use tab instead of space as indentation character.",
    )
    cmd_convert_arg_parser.add_argument(
        "--no-length", required=False, action="store_true", help="Do not create array length variable."
    )
    cmd_convert_arg_parser.add_argument(
        "--no-const", required=False, action="store_true", help="Do not use 'const' modifier for variables."
    )
    # SIGN_CMD command
    cmd_sign_arg_parser = subparsers.add_parser(SIGN_CMD, help="Sign manifest.")
    cmd_sign_arg_parser.add_argument("--input-file", required=True, help="Input SUIT file")
    cmd_sign_arg_parser.add_argument("--output-file", required=True, help="Output SUIT file")
    cmd_sign_arg_parser.add_argument("--private-key", required=True, help="Private key file")
    # IMAGE_CMD command
    cmd_image = subparsers.add_parser(
        IMAGE_CMD, help="Create hex files allowing boot or update execution path based on provided SUIT envelope."
    )

    cmd_image_subparsers = cmd_image.add_subparsers(dest=IMAGE_CMD, required=True, help="Choose image subcommand")
    cmd_image_boot = cmd_image_subparsers.add_parser(IMAGE_CMD_BOOT, help="Generate .hex files for boot execution path")
    cmd_image_update = cmd_image_subparsers.add_parser(
        IMAGE_CMD_UPDATE, help="Generate .hex files for update execution path"
    )

    cmd_image_boot.add_argument("--input-file", required=True, help="Input SUIT file; an envelope")
    cmd_image_boot.add_argument(
        "--storage-output-file", required=True, help="Output hex file with SUIT storage contents"
    )
    cmd_image_boot.add_argument(
        "--update-candidate-info-address",
        required=False,
        type=lambda x: int(x, 0),
        default=ImageCreator.default_update_candidate_info_address,
        help=f"Address of SUIT storage update candidate info. "
        f"Default: 0x{ImageCreator.default_update_candidate_info_address:08X}",
    )
    cmd_image_boot.add_argument(
        "--envelope-address",
        required=False,
        type=lambda x: int(x, 0),
        default=ImageCreator.default_envelope_address,
        help=f"Address of installed envelope in SUIT storage. Default: 0x{ImageCreator.default_envelope_address:08X}",
    )
    cmd_image_boot.add_argument(
        "--dfu-max-caches",
        required=False,
        type=int,
        default=ImageCreator.default_dfu_max_caches,
        help=f"Max number of DFU caches. Default: {ImageCreator.default_dfu_max_caches}",
    )

    cmd_image_update.add_argument("--input-file", required=True, help="Input SUIT file; an envelope")
    cmd_image_update.add_argument(
        "--storage-output-file", required=True, help="Output hex file with SUIT storage contents"
    )
    cmd_image_update.add_argument(
        "--dfu-partition-output-file", required=True, help="Output hex file with DFU partition contents"
    )
    cmd_image_update.add_argument(
        "--update-candidate-info-address",
        required=False,
        type=lambda x: int(x, 0),
        default=ImageCreator.default_update_candidate_info_address,
        help=f"Address of SUIT storage update candidate info. "
        f"Default: 0x{ImageCreator.default_update_candidate_info_address:08X}",
    )
    cmd_image_update.add_argument(
        "--dfu-partition-address",
        required=False,
        type=lambda x: int(x, 0),
        default=ImageCreator.default_dfu_partition_address,
        help=f"Address of partition where DFU update candidate is stored. "
        f"Default: 0x{ImageCreator.default_dfu_partition_address:08X}",
    )
    cmd_image_update.add_argument(
        "--dfu-max-caches",
        required=False,
        type=int,
        default=ImageCreator.default_dfu_max_caches,
        help=f"Max number of DFU caches. Default: {ImageCreator.default_dfu_max_caches}",
    )
    return parser


def parse_arguments() -> Tuple:
    """
    Parse CLI parameters.

    Parse passed CLI parameters and return argparse.Namespace

    :return: Tuple contains command and it's parameters
    """
    parser = _parser()
    arguments = parser.parse_args()
    cmd = str(arguments.command)

    # remove unnecessary arguments to simplify command calling
    del arguments.command

    # TODO: Refactor - workaround for fixed mapping between args and main's parameters
    if cmd == IMAGE_CMD:
        if arguments.image == IMAGE_CMD_BOOT:
            # Stub missing arguments from "update" subcommand
            arguments.dfu_partition_address = None
            arguments.dfu_partition_output_file = None
        elif arguments.image == IMAGE_CMD_UPDATE:
            # Stub missing arguments from "boot" subcommand
            arguments.envelope_address = None
        else:
            raise GeneratorError(f"Invalid 'image' subcommand: {arguments.image}")

    return cmd, arguments
