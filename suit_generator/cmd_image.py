#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Use SUIT envelope to generate hex files allowing boot/update execution path."""

import os
import struct

from cbor2 import dumps as cbor_dumps
from intelhex import IntelHex, bin2hex

from suit_generator.envelope import SuitEnvelope
from suit_generator.exceptions import GeneratorError
from suit_generator.exceptions import SUITError
from suit_generator.suit.manifest import SuitManifest


class ImageCreator:
    """Helper class for extracting data from SUIT envelope and creating hex files."""

    ENVELOPE_SLOT_VERSION = 1
    ENVELOPE_SLOT_VERSION_KEY = 0
    ENVELOPE_SLOT_CLASS_ID_OFFSET_KEY = 1
    ENVELOPE_SLOT_ENVELOPE_BSTR_KEY = 2

    default_update_candidate_info_address = 0x0E1EEC00
    default_envelope_address = 0x0E1EED80
    default_dfu_partition_address = 0x0E100000
    default_dfu_max_caches = 4

    UPDATE_MAGIC_VALUE_AVAILABLE = 0x55AA55AA

    IMAGE_CMD = "image"
    IMAGE_CMD_BOOT = "boot"
    IMAGE_CMD_UPDATE = "update"

    @staticmethod
    def _prepare_suit_storage_struct_format(dfu_max_caches: int) -> str:
        # Little endian,
        # 2x uint32_t for suit_storage magic and nb of memory regions fields,
        # (void*, size_t) for envelope address and size,
        # (void*, size_t) for each cache
        return "<" + "IIII" + dfu_max_caches * "II"

    @staticmethod
    def _prepare_update_candidate_info_for_boot(dfu_max_caches: int) -> bytes:
        uci = struct.Struct(ImageCreator._prepare_suit_storage_struct_format(dfu_max_caches))

        all_cache_values = dfu_max_caches * [0, 0]  # address, size
        struct_values = [
            ImageCreator.UPDATE_MAGIC_VALUE_AVAILABLE,  # Update candidate info magic
            0,  # Nb of memory regions
            0,  # SUIT envelope address
            0,  # SUIT envelope size
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
            1,  # Nb of memory regions
            dfu_partition_address,  # SUIT envelope address
            candidate_size,  # SUIT envelope size
            *all_cache_values,  # Values for all the caches
        ]

        return uci.pack(*struct_values)

    @staticmethod
    def _prepare_envelope_slot_binary(envelope: SuitEnvelope) -> bytes:
        severed_envelope = envelope.prepare_suit_data(envelope._envelope)
        manifest_dict = envelope._envelope["SUIT_Envelope_Tagged"]["suit-manifest"]

        if "suit-manifest-component-id" not in manifest_dict.keys():
            raise GeneratorError("The suit-manifest-component-id manifest field is mandatory")

        # Generate a key-value pair with manifest component ID to find its offset inside installed envelope
        manifest_component_id = manifest_dict["suit-manifest-component-id"]
        manifest_dict = {"suit-manifest-component-id": manifest_component_id}
        manifest_cbor = SuitManifest.from_obj(manifest_dict).to_cbor()

        # Cut the CBOR dictionary element count and find the key-value pair offset
        component_id_offset = severed_envelope.find(manifest_cbor[1:])

        # Move the offset, cutting the common prefix to get the offset to the raw UUID
        class_id_offset = component_id_offset + len(cbor_dumps([cbor_dumps("INSTLD_MFST"), b"#"]))

        envelope_slot = {
            ImageCreator.ENVELOPE_SLOT_VERSION_KEY: ImageCreator.ENVELOPE_SLOT_VERSION,
            ImageCreator.ENVELOPE_SLOT_CLASS_ID_OFFSET_KEY: class_id_offset,
            ImageCreator.ENVELOPE_SLOT_ENVELOPE_BSTR_KEY: severed_envelope,
        }

        return cbor_dumps(envelope_slot)

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
        envelope_hex.frombytes(ImageCreator._prepare_envelope_slot_binary(envelope), installed_envelope_address)

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
