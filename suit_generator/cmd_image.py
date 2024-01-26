#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Use SUIT envelope to generate hex files allowing boot/update execution path."""

from __future__ import annotations

import os
import struct
import uuid
from enum import Enum

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
        "--storage-output-directory", required=True, help="Output hex file with SUIT storage contents"
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
        "--envelope-slot-count",
        required=False,
        type=lambda x: int(x, 0),
        default=ImageCreator.default_envelope_slot_count,
        help=f"Max number of envelope slots in SUIT storage. Default: {ImageCreator.default_envelope_slot_count}",
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


class ManifestRole(Enum):
    """Role of the manifest inside the system."""

    UNKNOWN = 0x00
    SEC_TOP = 0x10
    SEC_SDFW = 0x11
    SEC_SYSCTRL = 0x12
    APP_ROOT = 0x20
    APP_RECOVERY = 0x21
    APP_LOCAL_1 = 0x22
    APP_LOCAL_2 = 0x23
    APP_LOCAL_3 = 0x24
    RAD_RECOVERY = 0x30
    RAD_LOCAL_1 = 0x31
    RAD_LOCAL_2 = 0x32


class ManifestDomain(Enum):
    """Domains in the system."""

    SECURE = 0x10
    APPLICATION = 0x20
    RADIO = 0x30


class EnvelopeStorage:
    """Class generating SUIT storage binary in legacy format."""

    ENVELOPE_SLOT_VERSION = 1
    ENVELOPE_SLOT_VERSION_KEY = 0
    ENVELOPE_SLOT_CLASS_ID_OFFSET_KEY = 1
    ENVELOPE_SLOT_ENVELOPE_BSTR_KEY = 2

    _LAYOUT = [
        {
            "role": ManifestRole.APP_ROOT,
            "offset": 2048 * 0,
            "size": 2048,
            "domain": ManifestDomain.APPLICATION,
        },
        {
            "role": ManifestRole.APP_LOCAL_1,
            "offset": 2048 * 1,
            "size": 2048,
            "domain": ManifestDomain.APPLICATION,
        },
        {
            "role": ManifestRole.RAD_LOCAL_1,
            "offset": 2048 * 2,
            "size": 2048,
            "domain": ManifestDomain.RADIO,
        },
        {
            "role": ManifestRole.SEC_TOP,
            "offset": 2048 * 3,
            "size": 2048,
            "domain": ManifestDomain.SECURE,
        },
        {
            "role": ManifestRole.SEC_SDFW,
            "offset": 2048 * 4,
            "size": 2048,
            "domain": ManifestDomain.SECURE,
        },
        {
            "role": ManifestRole.SEC_SYSCTRL,
            "offset": 2048 * 5,
            "size": 2048,
            "domain": ManifestDomain.SECURE,
        },
    ]

    # Default manifest role assignments
    _CLASS_ROLE_ASSIGNMENTS = [
        {
            "vendor_name": "nordicsemi.com",
            "class_name": "nRF54H20_sample_root",
            "role": ManifestRole.APP_ROOT,
        },
        {
            "vendor_name": "nordicsemi.com",
            "class_name": "nRF54H20_sample_app",
            "role": ManifestRole.APP_LOCAL_1,
        },
        {
            "vendor_name": "nordicsemi.com",
            "class_name": "nRF54H20_sample_rad",
            "role": ManifestRole.RAD_LOCAL_1,
        },
        {
            "vendor_name": "nordicsemi.com",
            "class_name": "nRF54H20_nordic_top",
            "role": ManifestRole.SEC_TOP,
        },
        {
            "vendor_name": "nordicsemi.com",
            "class_name": "nRF54H20_sec",
            "role": ManifestRole.SEC_SDFW,
        },
        {
            "vendor_name": "nordicsemi.com",
            "class_name": "nRF54H20_sys",
            "role": ManifestRole.SEC_SYSCTRL,
        },
    ]

    def __init__(self, base_address: int, load_defaults=True):
        """Create object generating binary SUIT storage."""
        self._assignments = []
        self._base_address = base_address
        self._envelopes = {}

        if load_defaults:
            for entry in self._CLASS_ROLE_ASSIGNMENTS:
                self.assign_role(entry["vendor_name"], entry["class_name"], entry["role"])

    def assign_role(self, vendor_name: str, class_name: str, role: ManifestRole):
        """Assign role to envelope, identified by vendor and class name."""
        vid = uuid.uuid5(uuid.NAMESPACE_DNS, vendor_name)
        self._assignments.append(
            {
                "vendor_id": vid.bytes,
                "class_id": uuid.uuid5(vid, class_name).bytes,
                "role": role,
            }
        )

    def _find_class(self, role: ManifestRole) -> bytes:
        for entry in self._assignments:
            if entry["role"] == role:
                return entry["class_id"]
        return None

    def _find_role(self, class_id: bytes) -> ManifestRole:
        for entry in self._assignments:
            if entry["class_id"].hex() == class_id.hex():
                return entry["role"]
        return None

    def _find_slot(self, class_id: bytes) -> (int, int):
        role = self._find_role(class_id)
        if role is not None:
            for entry in self._LAYOUT:
                if entry["role"] == role:
                    return (entry["offset"], entry["size"])
        return None

    def add_envelope(self, envelope: SuitEnvelope):
        """Add binary envelope to the SUIT storage."""
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
            EnvelopeStorage.ENVELOPE_SLOT_VERSION_KEY: EnvelopeStorage.ENVELOPE_SLOT_VERSION,
            EnvelopeStorage.ENVELOPE_SLOT_CLASS_ID_OFFSET_KEY: class_id_offset,
            EnvelopeStorage.ENVELOPE_SLOT_ENVELOPE_BSTR_KEY: severed_envelope,
        }

        envelope_bytes = cbor_dumps(envelope_slot)
        class_id = severed_envelope[class_id_offset : class_id_offset + 16]

        role = self._find_role(class_id)
        if role is None:
            raise GeneratorError(
                f"Unable to identify role for manifest with class id {class_id.hex()} / {self._assignments}"
            )

        slot = self._find_slot(class_id)
        if slot is None:
            raise GeneratorError(f"Unable to find slot for manifest with class id {class_id.hex()}")

        if slot[1] < len(envelope_bytes):
            raise GeneratorError(f"Unable to fit manifest with class id ({len(class_id.hex())} > {slot})")

        if role in self._envelopes.keys():
            raise GeneratorError(f"Manifest with role {role} already added")

        self._envelopes[role] = envelope_bytes

    def as_intelhex(self, storage_domain: ManifestDomain = None):
        """Export SUIT storage in Intel HEX format."""
        combined_hex = IntelHex()
        envelope_count = 0

        for entry in self._LAYOUT:
            max_size = entry["size"]
            role = entry["role"]
            domain = entry["domain"]

            if storage_domain is not None and storage_domain != domain:
                continue

            if role in self._envelopes:
                if len(self._envelopes[role]) > max_size:
                    raise GeneratorError(
                        f"Unable to fit envelope with role {role} inside the envelope slot (max: {max_size} bytes)"
                    )
                envelope_bytes = self._envelopes[role].ljust(max_size, b"\xFF")
                envelope_count += 1
            else:
                envelope_bytes = b"\xFF" * max_size

            envelope_hex = IntelHex()
            envelope_hex.frombytes(envelope_bytes, self._base_address + entry["offset"])

            combined_hex.merge(envelope_hex)

        if envelope_count <= 0:
            return None

        return combined_hex


class EnvelopeStorageV2(EnvelopeStorage):
    """Class generating SUIT storage binary in upcoming format."""

    _LAYOUT = [
        {
            "role": ManifestRole.SEC_TOP,
            "offset": 768,
            "size": 1280,
            "domain": ManifestDomain.SECURE,
        },
        {
            "role": ManifestRole.SEC_SDFW,
            "offset": 2048,
            "size": 1024,
            "domain": ManifestDomain.SECURE,
        },
        {
            "role": ManifestRole.SEC_SYSCTRL,
            "offset": 3072,
            "size": 1024,
            "domain": ManifestDomain.SECURE,
        },
        {
            "role": ManifestRole.RAD_RECOVERY,
            "offset": 4096 + 1024 * 1,
            "size": 1024,
            "domain": ManifestDomain.RADIO,
        },
        {
            "role": ManifestRole.RAD_LOCAL_1,
            "offset": 4096 + 1024 * 2,
            "size": 1024,
            "domain": ManifestDomain.RADIO,
        },
        {
            "role": ManifestRole.RAD_LOCAL_2,
            "offset": 4096 + 1024 * 3,
            "size": 1024,
            "domain": ManifestDomain.RADIO,
        },
        {
            "role": ManifestRole.APP_ROOT,
            "offset": 8192 + 1024 * 1,
            "size": 2048,
            "domain": ManifestDomain.APPLICATION,
        },
        {
            "role": ManifestRole.APP_RECOVERY,
            "offset": 8192 + 1024 * 3,
            "size": 2048,
            "domain": ManifestDomain.APPLICATION,
        },
        {
            "role": ManifestRole.APP_LOCAL_1,
            "offset": 8192 + 1024 * 5,
            "size": 1024,
            "domain": ManifestDomain.APPLICATION,
        },
        {
            "role": ManifestRole.APP_LOCAL_2,
            "offset": 8192 + 1024 * 6,
            "size": 1024,
            "domain": ManifestDomain.APPLICATION,
        },
        {
            "role": ManifestRole.APP_LOCAL_3,
            "offset": 8192 + 1024 * 7,
            "size": 1024,
            "domain": ManifestDomain.APPLICATION,
        },
    ]


class ImageCreator:
    """Helper class for extracting data from SUIT envelope and creating hex files."""

    default_update_candidate_info_address = 0x0E1E7000
    default_envelope_address = 0x0E1E7180
    default_envelope_slot_size = 2048
    default_envelope_slot_count = 8
    default_dfu_partition_address = 0x0E155000
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
    def _create_single_domain_storage_file_for_boot(
        storage: EnvelopeStorage,
        domain: ManifestDomain,
        dir_name: str,
        additional_hex,
    ) -> None:
        combined_hex = IntelHex()
        if additional_hex is not None:
            combined_hex = IntelHex(additional_hex)

        envelopes_hex = storage.as_intelhex(domain)

        if envelopes_hex is not None:
            combined_hex.merge(envelopes_hex)
            combined_hex.write_hex_file(dir_name + "/storage_" + domain.name.lower() + ".hex")

    def _create_suit_storage_file_for_boot_legacy(
        envelopes: list[SuitEnvelope],
        update_candidate_info_address: int,
        installed_envelope_address: int,
        envelope_slot_size: int,
        envelope_slot_count: int,
        dir_name: str,
        dfu_max_caches: int,
    ) -> None:
        # Update candidate info
        # In the boot path it is used to inform no update candidate is pending.
        uci_hex = IntelHex()
        uci_hex.frombytes(
            ImageCreator._prepare_update_candidate_info_for_boot(dfu_max_caches), update_candidate_info_address
        )

        combined_hex = IntelHex(uci_hex)

        storage = EnvelopeStorage(installed_envelope_address)
        for envelope in envelopes:
            storage.add_envelope(envelope)
        combined_hex.merge(storage.as_intelhex())

        combined_hex.write_hex_file(dir_name + "/storage.hex")

    @staticmethod
    def _create_suit_storage_files_for_boot(
        envelopes: list[SuitEnvelope],
        update_candidate_info_address: int,
        installed_envelope_address: int,
        envelope_slot_size: int,
        envelope_slot_count: int,
        dir_name: str,
        dfu_max_caches: int,
    ) -> None:
        # Update candidate info
        # In the boot path it is used to inform no update candidate is pending.
        uci_hex = IntelHex()
        uci_hex.frombytes(
            ImageCreator._prepare_update_candidate_info_for_boot(dfu_max_caches), update_candidate_info_address
        )

        storage = EnvelopeStorage(installed_envelope_address)
        for envelope in envelopes:
            storage.add_envelope(envelope)

        for domain in ManifestDomain:
            additional_hex = None
            if domain == ManifestDomain.APPLICATION:
                additional_hex = uci_hex
            ImageCreator._create_single_domain_storage_file_for_boot(storage, domain, dir_name, additional_hex)

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
        storage_output_directory: str,
        update_candidate_info_address: int,
        envelope_address: int,
        envelope_slot_size: int,
        envelope_slot_count: int,
        dfu_max_caches: int,
    ) -> None:
        """Create storage and payload hex files allowing boot execution path.

        :param input_file: file path to SUIT envelope
        :param storage_output_directory: directory path to store hex files with SUIT storage contents
        :param update_candidate_info_address: address of SUIT storage update candidate info
        :param envelope_address: address of installed envelope in SUIT storage
        :param envelope_slot_size: number of bytes, reserved to store a single envelope,
        :param envelope_slot_count: number of envelope slots in SUIT storage,
        :param dfu_max_caches: maximum number of caches, allowed to be passed inside update candidate info,
        """
        try:
            envelopes = []
            for input_file in input_files:
                envelope = SuitEnvelope()
                envelope.load(input_file, "suit")

                envelope.sever()
                envelopes.append(envelope)

            ImageCreator._create_suit_storage_file_for_boot_legacy(
                envelopes,
                update_candidate_info_address,
                envelope_address,
                envelope_slot_size,
                envelope_slot_count,
                storage_output_directory,
                dfu_max_caches,
            )
            ImageCreator._create_suit_storage_files_for_boot(
                envelopes,
                update_candidate_info_address,
                envelope_address,
                envelope_slot_size,
                envelope_slot_count,
                storage_output_directory,
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
        * **storage_output_file** - file path to hex file with SUIT storage contents - for "update" command
        * **storage_output_directory** - directory path to store hex files with storage contents - for "boot" command
        * **update_candidate_info_address** - address of SUIT storage update candidate info
        * **envelope_address** - address of installed envelope in SUIT storage
        * **dfu_partition_output_file** - file path to hex file with DFU partition contents (the SUIT envelope)
        * **dfu_partition_address** - address of partition where DFU update candidate is stored
    """
    if kwargs["image"] == ImageCreator.IMAGE_CMD_BOOT:
        ImageCreator.create_files_for_boot(
            kwargs["input_file"],
            kwargs["storage_output_directory"],
            kwargs["update_candidate_info_address"],
            kwargs["envelope_address"],
            kwargs["envelope_slot_size"],
            kwargs["envelope_slot_count"],
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
