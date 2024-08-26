#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""CMD_CACHE_CREATE CLI command entry point."""

import logging
import cbor2
import math

log = logging.getLogger(__name__)

CACHE_CREATE_CMD = "cache_create"

def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_cache_create_arg_parser = parser.add_parser(CACHE_CREATE_CMD, help="Create raw cache structure.")

    cmd_cache_create_arg_parser.add_argument(
        "--input", required=True, action="append",
        help="Input binary with corresponding URI, passed in format <URI>,<INPUT_FILE_PATH>."
        + "Multiple inputs can be passed."
    )
    cmd_cache_create_arg_parser.add_argument("--output-file", required=True, help="Output raw SUIT DFU cache file.")
    cmd_cache_create_arg_parser.add_argument("--eb-size", type=int, help="Erase block size in bytes (used for padding).",
                                             default=16)


def add_padding(data: bytes, eb_size: int) -> bytes:
    data_len = len(data)

    rounded_up_size = math.ceil(len(data) / eb_size) * eb_size
    padding_size = rounded_up_size - len(data)
    padded_data = data

    # minimum padding size is 2 bytes
    if padding_size == 1:
        padding_size += eb_size
        rounded_up_size += eb_size

    if padding_size == 0:
        return data

    padded_data += bytes([0x60])

    if padding_size <= 23:
        header_len = 2
        padded_data += bytes([0x40 + (padding_size - header_len)])
    elif padding_size <= 0xFFFF:
        header_len = 4
        padded_data += bytes([0x59]) + (padding_size - header_len).to_bytes(2, byteorder='big')
    else:
        raise ValueError("Number of required padding bytes exceeds assumed max size 0xFFFF")

    return padded_data.ljust(rounded_up_size, b'\x00')

def main(input: list[str], output_file: str, eb_size: int) -> None:
    # """Create raw SUIT DFU Cache.

    # :param input: list of input files with corresponding URIs in format <URI>,<INPUT_FILE_PATH>
    # :param output_file: output file path

    cache_data = bytes()
    first_slot = True

    for single_input in input:
        args = single_input.split(",")
        if len(args) < 2:
            raise ValueError("Invalid number of input arguments: " + single_input)
        uri, input_file = args

        data = None
        with open(input_file, "rb") as f:
            data = f.read()

        slot_data = bytes()
        if first_slot:
            # Open the cache - it is an indefinite length CBOR map (0xBF)
            slot_data = bytes([0xBF])
            first_slot = False

        # uri as key
        slot_data += cbor2.dumps(uri)

        # Size must be encoded in 4 bytes, thus cannot use cbor2.dumps
        slot_data += bytes([0x5A]) + len(data).to_bytes(4, byteorder='big') + data
        # Add padding for single slot
        slot_data = add_padding(slot_data, eb_size)

        cache_data += slot_data

    cache_data += bytes([0xFF])  # Finish the indefinite length map

    with open(output_file, "wb") as f:
        f.write(cache_data)
