#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Use SUIT envelope to generate hex files allowing boot/update execution path."""

import os
import struct

from intelhex import IntelHex, bin2hex

from suit_generator.envelope import SuitEnvelope
from suit_generator.exceptions import GeneratorError
from suit_generator.exceptions import SUITError


class ImageCreator:
    """Helper class for extracting data from SUIT envelope and creating hex files."""

    default_update_candidate_info_address = 0x0E1FE000
    default_envelope_address = 0x0E1FF000
    default_dfu_partition_address = 0x0E100000
    default_dfu_max_caches = 4

    UPDATE_MAGIC_VALUE_CLEARED = 0xAAAA5555
    UPDATE_MAGIC_VALUE_AVAILABLE = 0x5555AAAA

    IMAGE_CMD = "image"
    IMAGE_CMD_BOOT = "boot"
    IMAGE_CMD_UPDATE = "update"

    @staticmethod
    def _prepare_suit_storage_struct_format(dfu_max_caches: int) -> str:
        # Little endian,
        # 3x uint32_t for suit_storage info fields,
        # 1x uint8_t for number of used caches,
        # (size_t, void*) for each cache
        return "<" + "III" + "B" + dfu_max_caches * "II"

    @staticmethod
    def _prepare_update_candidate_info_for_boot(dfu_max_caches: int) -> bytes:
        uci = struct.Struct(ImageCreator._prepare_suit_storage_struct_format(dfu_max_caches))

        all_cache_values = dfu_max_caches * [0, 0]  # size, address
        struct_values = [
            ImageCreator.UPDATE_MAGIC_VALUE_CLEARED,  # Update candidate info magic
            0,  # Update candidate info address
            0,  # Update candidate info size
            0,  # Nb of caches
            *all_cache_values,  # Values for all the caches
        ]

        return uci.pack(*struct_values)

    @staticmethod
    def _prepare_update_candidate_info_for_update(
        dfu_partition_address: int, candidate_size: int, dfu_max_caches: int
    ) -> bytes:
        uci = struct.Struct(ImageCreator._prepare_suit_storage_struct_format(dfu_max_caches))

        all_cache_values = dfu_max_caches * [0, 0]  # size, address
        struct_values = [
            ImageCreator.UPDATE_MAGIC_VALUE_AVAILABLE,  # Update candidate info: magic
            dfu_partition_address,  # Update candidate info: address
            candidate_size,  # Update candidate info: size
            0,  # Nb of caches
            *all_cache_values,  # Values for all the caches
        ]

        return uci.pack(*struct_values)

    @staticmethod
    def _create_suit_storage_file_for_boot(
        envelope: SuitEnvelope,
        update_candidate_info_address: int,
        installed_envelope_address: int,
        file_name: str,
        dfu_max_caches: int,
    ) -> None:
        # Update candidate info
        uci_hex = IntelHex()
        uci_hex.frombytes(
            ImageCreator._prepare_update_candidate_info_for_boot(dfu_max_caches), update_candidate_info_address
        )

        # Installed envelope
        envelope_hex = IntelHex()
        envelope_hex.frombytes(envelope.prepare_suit_data(envelope._envelope), installed_envelope_address)

        # The suit storage file for boot path combines update candidate info and installed envelope
        combined_hex = IntelHex(uci_hex)
        combined_hex.merge(envelope_hex)
        combined_hex.write_hex_file(file_name)

    @staticmethod
    def _create_suit_storage_file_for_update(
        dfu_partition_address: int,
        update_candidate_size: int,
        update_candidate_info_address: int,
        file_name: str,
        dfu_max_caches: int,
    ) -> None:
        # The suit storage file for update path contains only update candidate info; installed envelope is not touched
        uci_hex = IntelHex()
        uci_hex.frombytes(
            ImageCreator._prepare_update_candidate_info_for_update(
                dfu_partition_address, update_candidate_size, dfu_max_caches
            ),
            update_candidate_info_address,
        )
        uci_hex.write_hex_file(file_name)

    @staticmethod
    def _create_dfu_partition_hex_file(input_file: str, dfu_partition_output_file: str, dfu_partition_address) -> None:
        if err := bin2hex(input_file, dfu_partition_output_file, dfu_partition_address):
            raise GeneratorError(f"Failed to convert {input_file} to {dfu_partition_output_file}: {err}")

    @staticmethod
    def create_files_for_boot(
        input_file: str,
        storage_output_file: str,
        update_candidate_info_address: int,
        envelope_address: int,
        dfu_max_caches: int,
    ) -> None:
        """Create storage and payload hex files allowing boot execution path.

        :param input_file: file path to SUIT envelope
        :param storage_output_file: file path to hex file with SUIT storage contents
        :param update_candidate_info_address: address of SUIT storage update candidate info
        :param envelope_address: address of installed envelope in SUIT storage
        """
        try:
            envelope = SuitEnvelope()
            envelope.load(input_file, "suit")

            envelope.sever()

            ImageCreator._create_suit_storage_file_for_boot(
                envelope, update_candidate_info_address, envelope_address, storage_output_file, dfu_max_caches
            )
        except FileNotFoundError as error:
            raise GeneratorError(error)
        except AttributeError as error:
            raise SUITError(error)

    @staticmethod
    def create_files_for_update(
        input_file: str,
        storage_output_file: str,
        dfu_partition_output_file: str,
        update_candidate_info_address: int,
        dfu_partition_address: int,
        dfu_max_caches: int,
    ):
        """Create SUIT storage and DFU partition hex files allowing update execution path.

        :param input_file: file path to SUIT envelope
        :param storage_output_file: file path to hex file with SUIT storage contents
        :param dfu_partition_output_file: file path to hex file with DFU partition contents (the SUIT envelope)
        :param update_candidate_info_address: address of SUIT storage update candidate info
        :param dfu_partition_address: address of partition where DFU update candidate is stored
        """
        try:
            ImageCreator._create_suit_storage_file_for_update(
                dfu_partition_address,
                os.path.getsize(input_file),
                update_candidate_info_address,
                storage_output_file,
                dfu_max_caches,
            )
            ImageCreator._create_dfu_partition_hex_file(input_file, dfu_partition_output_file, dfu_partition_address)
        except FileNotFoundError as error:
            raise GeneratorError(error)


def main(
    image: str,
    input_file: str,
    storage_output_file: str,
    update_candidate_info_address: int,
    envelope_address: int,
    dfu_partition_output_file: str,
    dfu_partition_address: int,
    dfu_max_caches: int,
) -> None:
    """Create hex files allowing boot or update execution path.

    :param image: subcommand to be executed

    :param input_file: file path to SUIT envelope
    :param storage_output_file: file path to hex file with SUIT storage contents
    :param update_candidate_info_address: address of SUIT storage update candidate info
    :param envelope_address: address of installed envelope in SUIT storage
    :param dfu_partition_output_file: file path to hex file with DFU partition contents (the SUIT envelope)
    :param dfu_partition_address: address of partition where DFU update candidate is stored
    """
    if image == ImageCreator.IMAGE_CMD_BOOT:
        ImageCreator.create_files_for_boot(
            input_file,
            storage_output_file,
            update_candidate_info_address,
            envelope_address,
            dfu_max_caches,
        )
    elif image == ImageCreator.IMAGE_CMD_UPDATE:
        ImageCreator.create_files_for_update(
            input_file,
            storage_output_file,
            dfu_partition_output_file,
            update_candidate_info_address,
            dfu_partition_address,
            dfu_max_caches,
        )
    else:
        raise GeneratorError(f"Invalid 'image' subcommand: {image}")
