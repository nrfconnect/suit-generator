#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Use SUIT envelope to generate hex files allowing boot/update execution path."""

from __future__ import annotations

import os
import struct

from cbor2 import dumps as cbor_dumps
from intelhex import IntelHex, bin2hex

from suit_generator.envelope import SuitEnvelope
from suit_generator.exceptions import GeneratorError
from suit_generator.exceptions import SUITError
from suit_generator.suit.manifest import SuitManifest


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_image = parser.add_parser(
        ImageCreator.IMAGE_CMD,
        help="Create hex files allowing boot or update execution path based on provided SUIT envelope.",
    )

    cmd_image_subparsers = cmd_image.add_subparsers(
        dest=ImageCreator.IMAGE_CMD, required=True, help="Choose image subcommand"
    )
    cmd_image_boot = cmd_image_subparsers.add_parser(
        ImageCreator.IMAGE_CMD_BOOT, help="Generate .hex files for boot execution path"
    )
    cmd_image_update = cmd_image_subparsers.add_parser(
        ImageCreator.IMAGE_CMD_UPDATE, help="Generate .hex files for update execution path"
    )

    cmd_image_boot.add_argument("--input-file", required=True, action="append", help="Input SUIT file; an envelope")
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
        "--envelope-slot-size",
        required=False,
        type=lambda x: int(x, 0),
        default=ImageCreator.default_envelope_slot_size,
        help=f"Envelope slot size in SUIT storage. Default: 0x{ImageCreator.default_envelope_slot_size:08X}",
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


class ImageCreator:
    """Helper class for extracting data from SUIT envelope and creating hex files."""

    ENVELOPE_SLOT_VERSION = 1
    ENVELOPE_SLOT_VERSION_KEY = 0
    ENVELOPE_SLOT_CLASS_ID_OFFSET_KEY = 1
    ENVELOPE_SLOT_ENVELOPE_BSTR_KEY = 2

    default_update_candidate_info_address = 0x0E1EEC00
    default_envelope_address = 0x0E1EED80
    default_envelope_slot_size = 2048
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
        envelopes: list[SuitEnvelope],
        update_candidate_info_address: int,
        installed_envelope_address: int,
        envelope_slot_size: int,
        file_name: str,
        dfu_max_caches: int,
    ) -> None:
        # Update candidate info
        uci_hex = IntelHex()
        uci_hex.frombytes(
            ImageCreator._prepare_update_candidate_info_for_boot(dfu_max_caches), update_candidate_info_address
        )

        # The suit storage file for boot path combines update candidate info and installed envelope
        combined_hex = IntelHex(uci_hex)

        # Installed envelopes
        envelope_address = installed_envelope_address

        for envelope in envelopes:
            envelope_bytes = ImageCreator._prepare_envelope_slot_binary(envelope)
            if len(envelope_bytes) > envelope_slot_size:
                raise GeneratorError(
                    f"Input envelope ({envelope}) exceeds slot size ({len(envelope_bytes)} > {envelope_slot_size})."
                )

            envelope_hex = IntelHex()
            envelope_hex.frombytes(envelope_bytes, envelope_address)

            combined_hex.merge(envelope_hex)
            envelope_address += envelope_slot_size

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
        input_files: list[str],
        storage_output_file: str,
        update_candidate_info_address: int,
        envelope_address: int,
        envelope_slot_size: int,
        dfu_max_caches: int,
    ) -> None:
        """Create storage and payload hex files allowing boot execution path.

        :param input_file: file path to SUIT envelope
        :param storage_output_file: file path to hex file with SUIT storage contents
        :param update_candidate_info_address: address of SUIT storage update candidate info
        :param envelope_address: address of installed envelope in SUIT storage
        """
        try:
            envelopes = []
            for input_file in input_files:
                envelope = SuitEnvelope()
                envelope.load(input_file, "suit")

                envelope.sever()
                envelopes.append(envelope)

            ImageCreator._create_suit_storage_file_for_boot(
                envelopes,
                update_candidate_info_address,
                envelope_address,
                envelope_slot_size,
                storage_output_file,
                dfu_max_caches,
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


def main(**kwargs) -> None:
    """Create hex files allowing boot or update execution path.

    :Keyword Arguments:
        * **image** - subcommand to be executed
        * **input_file** - file path to SUIT envelope
        * **storage_output_file** - file path to hex file with SUIT storage contents
        * **update_candidate_info_address** - address of SUIT storage update candidate info
        * **envelope_address** - address of installed envelope in SUIT storage
        * **dfu_partition_output_file** - file path to hex file with DFU partition contents (the SUIT envelope)
        * **dfu_partition_address** - address of partition where DFU update candidate is stored
    """
    if kwargs["image"] == ImageCreator.IMAGE_CMD_BOOT:
        ImageCreator.create_files_for_boot(
            kwargs["input_file"],
            kwargs["storage_output_file"],
            kwargs["update_candidate_info_address"],
            kwargs["envelope_address"],
            kwargs["envelope_slot_size"],
            kwargs["dfu_max_caches"],
        )
    elif kwargs["image"] == ImageCreator.IMAGE_CMD_UPDATE:
        ImageCreator.create_files_for_update(
            kwargs["input_file"],
            kwargs["storage_output_file"],
            kwargs["dfu_partition_output_file"],
            kwargs["update_candidate_info_address"],
            kwargs["dfu_partition_address"],
            kwargs["dfu_max_caches"],
        )
    else:
        raise GeneratorError(f"Invalid 'image' subcommand: {kwargs['image']}")
