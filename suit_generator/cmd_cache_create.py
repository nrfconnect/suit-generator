#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""CMD_CACHE_CREATE CLI command entry point."""

import logging
import math
import cbor2
import re

from suit_generator.exceptions import GeneratorError

CACHE_CREATE_CMD = "cache_create"
CACHE_CREATE_FROM_PAYLOADS_CMD = "from_payloads"
CACHE_CREATE_FROM_ENVELOPE_CMD = "from_envelope"
CACHE_MERGE_CMD = "merge"

log = logging.getLogger(__name__)


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_cache_create = parser.add_parser(CACHE_CREATE_CMD, help="Create raw cache structure.")

    cmd_cache_create_subparsers = cmd_cache_create.add_subparsers(
        dest="cache_create_subcommand", required=True, help="Choose cache_create subcommand"
    )
    cmd_cache_create_from_payloads = cmd_cache_create_subparsers.add_parser(
        CACHE_CREATE_FROM_PAYLOADS_CMD,
        help="Create a cache partition from the provided binaries containing raw payloads.",
    )

    cmd_cache_create_from_payloads.add_argument("--output-file", required=True, help="Output raw SUIT DFU cache file.")
    cmd_cache_create_from_payloads.add_argument(
        "--eb-size", type=int, help="Erase block size in bytes (used for padding).", default=16
    )

    cmd_cache_create_from_payloads.add_argument(
        "--input",
        required=True,
        action="append",
        help="Input binary with corresponding URI, passed in format <URI>,<INPUT_FILE_PATH>."
        + "Multiple inputs can be passed.",
    )

    cmd_cache_create_from_envelope = cmd_cache_create_subparsers.add_parser(
        CACHE_CREATE_FROM_ENVELOPE_CMD, help="Create a cache partition from the payloads inside the provided envelope."
    )

    cmd_cache_create_from_envelope.add_argument("--output-file", required=True, help="Output raw SUIT DFU cache file.")
    cmd_cache_create_from_envelope.add_argument(
        "--eb-size", type=int, help="Erase block size in bytes (used for padding).", default=16
    )

    cmd_cache_create_from_envelope.add_argument("--input-envelope", required=True, help="Input envelope file path.")

    cmd_cache_create_from_envelope.add_argument(
        "--output-envelope", required=True, help="Output envelope file path (envelope with removed extracted payloads)."
    )

    cmd_cache_create_from_envelope.add_argument(
        "--omit-payload-regex",
        help="Integrated payloads matching the regular expression will not be extracted to the cache.",
    )

    cmd_cache_create_from_envelope.add_argument(
        "--dependency-regex",
        help="Integrated payloads matching the regular expression will be treated as dependency"
        + "envelopes and parsed hierarchically. "
        + "The payloads extracted from the dependency envelopes will be added to the cache.",
    )

    cmd_cache_merge = cmd_cache_create_subparsers.add_parser(
        CACHE_MERGE_CMD, help="Merge multiple cache partitions into a single cache partition."
    )

    cmd_cache_merge.add_argument("--input", required=True, action="append", help="Input raw SUIT DFU cache file.")
    cmd_cache_merge.add_argument("--output-file", required=True, help="Output raw SUIT DFU cache file.")
    cmd_cache_merge.add_argument(
        "--eb-size", type=int, help="Erase block size in bytes (used for padding).", default=16
    )


class CachePartition:
    """Class generating SUIT DFU Cache Partition."""

    def __init__(self, eb_size: int):
        """Initialize a CachePartition object."""
        self.first_slot = True
        self.cache_data = bytes()
        self.eb_size = eb_size
        self.uris = []

    def add_padding(self, data: bytes) -> bytes:
        """
        Add padding to the given data to align it to the specified erase block size.

        This method ensures that the data is padded to a size that is a multiple of the erase block size (self.eb_size).
        The padding is done by appending a CBOR key-value pair with empty URI as the key and
        byte-string-encoded zeros as the value.

        :param data: The input data to be padded.
        :type data: bytes
        :return: The padded data.
        """
        rounded_up_size = math.ceil(len(data) / self.eb_size) * self.eb_size
        padding_size = rounded_up_size - len(data)
        padded_data = data

        # minimum padding size is 2 bytes
        if padding_size == 1:
            padding_size += self.eb_size
            rounded_up_size += self.eb_size

        if padding_size == 0:
            return data

        padded_data += bytes([0x60])

        if padding_size <= 23:
            header_len = 2
            padded_data += bytes([0x40 + (padding_size - header_len)])
        elif padding_size <= 0xFFFF:
            header_len = 4
            padded_data += bytes([0x59]) + (padding_size - header_len).to_bytes(2, byteorder="big")
        else:
            raise ValueError("Number of required padding bytes exceeds assumed max size 0xFFFF")

        return padded_data.ljust(rounded_up_size, b"\x00")

    def add_cache_slot(self, uri: str, data: bytes):
        """
        Add a cache slot to the cache from the given URI and data.

        This function creates a cache slot from the given URI and data, and pads the data to align with the specified
        erase block size (eb_size). The first slot in the cache is created with indefinite length CBOR map.

        :param uri: The URI associated with the data.
        :type uri: str
        :param data: The data to be included in the cache slot.
        :type data: bytes
        """
        slot_data = bytes()
        if self.first_slot:
            # Open the cache - it is an indefinite length CBOR map (0xBF)
            slot_data = bytes([0xBF])
            self.first_slot = False

        if uri in self.uris:
            raise ValueError(f"URI {uri} already exists in the cache!")
        self.uris.append(uri)

        # uri as key
        slot_data += cbor2.dumps(uri)

        # Size must be encoded in 4 bytes, thus cannot use cbor2.dumps
        slot_data += bytes([0x5A]) + len(data).to_bytes(4, byteorder="big") + data
        # Add padding for single slot
        slot_data = self.add_padding(slot_data)

        self.cache_data += slot_data

    def close_and_save_cache(self, output_file: str):
        """
        Close the cache and save it to the specified output file.

        This function closes the cache by adding the end-of-map byte (0xFF) and saves the cache to the specified output
        file.

        :param output_file: Path to the output raw SUIT DFU cache file.
        :type output_file: str
        """
        self.cache_data += bytes([0xFF])
        with open(output_file, "wb") as f:
            f.write(self.cache_data)

    def merge_single_cache_file(self, cache_input_file: str):
        """
        Merge the contents of the provided single cache file into the current cache.

        :param cache_input_file: Path to the input raw SUIT DFU cache file.
        """
        with open(cache_input_file, "rb") as f:
            data = f.read()

        cache_dict = cbor2.loads(data)

        for k in cache_dict.keys():
            if len(k) == 0:
                continue  # Empty key means padding - skip
            self.add_cache_slot(k, cache_dict[k])


class CacheFromPayloads:
    """Class generating SUIT DFU Cache Partition from payloads."""

    def fill_cache_from_payloads(cache: CachePartition, input: list[str]) -> None:
        """
        Process list of input binaries, each associated with a URI, and fill the SUIT DFU cache with the data.

        :param cache: CachePartition object to fill with the data
        :param input: List of input binaries with corresponding URIs, passed in the format <URI>,<INPUT_FILE_PATH>
        """
        for single_input in input:
            args = single_input.split(",")
            if len(args) < 2:
                raise ValueError("Invalid number of input arguments: " + single_input)
            uri, input_file = args

            with open(input_file, "rb") as f:
                data = f.read()

            cache.add_cache_slot(uri, data)


class CacheFromEnvelope:
    """Class generating SUIT DFU Cache Partition from envelope."""

    def fill_cache_from_envelope_data(
        cache: CachePartition, envelope_data: bytes, omit_payload_regex: str, dependency_regex: str
    ) -> bytes:
        """
        Fill the cache partition with data from the payloads inside the provided envelope binary data.

        This function is called recursively for dependency envelopes.
        :param cache: CachePartition object to fill with the data
        :param envelope_data: Binary data of the envelope to extract the payloads from
        :param omit_payload_regex: Integrated payloads matching the regular expression will not be extracted to the
                                   cache
        :param dependency_regex: Integrated payloads matching the regular expression will be treated as dependency
                                 envelopes
        """
        try:
            envelope = cbor2.loads(envelope_data)
        except Exception:
            raise GeneratorError("The provided envelope/dependency envelope is not a valid envelope!")

        if isinstance(envelope, cbor2.CBORTag) and isinstance(envelope.value, dict):
            integrated = [k for k in envelope.value.keys() if isinstance(k, str)]
        else:
            raise GeneratorError("The provided envelope/dependency envelope is not a valid envelope!")

        if dependency_regex is not None:
            integrated_dependencies = [k for k in integrated if not re.fullmatch(dependency_regex, k) is None]
            for dep in integrated_dependencies:
                integrated.remove(dep)
        else:
            integrated_dependencies = []

        if omit_payload_regex is None:
            payloads_to_extract = integrated
        else:
            payloads_to_extract = [k for k in integrated if re.fullmatch(omit_payload_regex, k) is None]

        for payload in payloads_to_extract:
            cache.add_cache_slot(payload, envelope.value.pop(payload))

        for dependency in integrated_dependencies:
            try:
                new_dependency_data = CacheFromEnvelope.fill_cache_from_envelope_data(
                    cache, envelope.value[dependency], omit_payload_regex, dependency_regex
                )
            except GeneratorError as e:
                log.log(logging.ERROR, "Failed to extract payloads from dependency %s: %s", dependency, repr(e))
                raise GeneratorError("Failed to extract payloads from envelope!")

            envelope.value[dependency] = new_dependency_data

        return cbor2.dumps(envelope)

    def fill_cache_from_envelope(
        cache: CachePartition, input_envelope: str, output_envelope: str, omit_payload_regex: str, dependency_regex: str
    ) -> None:
        """
        Extract the payloads from the provided envelope to the cache partition file.

        param cache: CachePartition object to fill with the data
        param input_envelope: Path to the input envelope file
        param output_envelope: Path to the output envelope file (envelope with removed extracted payloads)
        param omit_payload_regex: Integrated payloads matching the regular expression will not be extracted to the cache
        param dependency_regex: Integrated payloads matching the regular expression will be treated as dependency
                                envelopes
        """
        with open(input_envelope, "rb") as fh:
            data = fh.read()
        output_envelope_data = CacheFromEnvelope.fill_cache_from_envelope_data(
            cache, data, omit_payload_regex, dependency_regex
        )
        with open(output_envelope, "wb") as fh:
            fh.write(output_envelope_data)


class CacheMerge:
    """Class merging SUIT DFU Cache Partitions."""

    def merge_cache_files(cache: CachePartition, input: list[str]) -> None:
        """
        Merge the contents of the provided cache files into the cache partition.

        :param cache: CachePartition object to merge the cache files into
        :param input: List of paths to the input raw SUIT DFU cache files
        """
        for single_input in input:
            cache.merge_single_cache_file(single_input)


def main(**kwargs) -> None:
    """Create a raw SUIT DFU cache file."""
    cache = CachePartition(kwargs["eb_size"])

    if kwargs["cache_create_subcommand"] == CACHE_CREATE_FROM_PAYLOADS_CMD:
        CacheFromPayloads.fill_cache_from_payloads(cache, kwargs["input"])
    elif kwargs["cache_create_subcommand"] == CACHE_CREATE_FROM_ENVELOPE_CMD:
        CacheFromEnvelope.fill_cache_from_envelope(
            cache,
            kwargs["input_envelope"],
            kwargs["output_envelope"],
            kwargs["omit_payload_regex"],
            kwargs["dependency_regex"],
        )
    elif kwargs["cache_create_subcommand"] == CACHE_MERGE_CMD:
        CacheMerge.merge_cache_files(cache, kwargs["input"])
    else:
        raise GeneratorError(f"Invalid 'cache_create' subcommand: {kwargs['cache_create_subcommand']}")

    cache.close_and_save_cache(kwargs["output_file"])
