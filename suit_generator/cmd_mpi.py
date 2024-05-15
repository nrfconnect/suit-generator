#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""CMD_MPI CLI command entry point."""

from __future__ import annotations

import uuid
from intelhex import IntelHex
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from suit_generator.exceptions import GeneratorError

MPI_CMD = "mpi"
MPI_GENERATE = "generate"
MPI_MERGE = "merge"


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_mpi = parser.add_parser(
        MPI_CMD,
        help="Create hex files allowing to provision manifest information to the device.",
    )

    cmd_mpi_subparsers = cmd_mpi.add_subparsers(dest=MPI_CMD, required=True, help="Choose MPI subcommand")
    cmd_mpi_generate = cmd_mpi_subparsers.add_parser(
        MPI_GENERATE, help="Generate .hex Manifest Provisioning Information binary for a single manifest"
    )

    cmd_mpi_generate.add_argument("--output-file", required=True, help="Output file path.")
    cmd_mpi_generate.add_argument("--vendor-name", required=True, help="Vendor name to use for UUID generation.")
    cmd_mpi_generate.add_argument("--class-name", required=True, help="Device class name to use for UUID generation.")
    cmd_mpi_generate.add_argument(
        "--address",
        required=True,
        type=lambda x: int(x, 0),
        help="Address inside the internal memory of the generated MPI structure.",
    )
    cmd_mpi_generate.add_argument(
        "--size",
        required=True,
        type=lambda x: int(x, 0),
        help="Size of the memory, reserved for the MPI structure.",
    )

    cmd_mpi_generate.add_argument(
        "--downgrade-prevention-enabled",
        required=False,
        action="store_true",
        help="Enable downgrade prevention policy.",
    )
    cmd_mpi_generate.add_argument(
        "--independent-updates", required=False, action="store_true", help="Enable independent updateability."
    )
    cmd_mpi_generate.add_argument(
        "--signature-verification",
        required=False,
        choices=["update", "update-and-boot"],
        help="Enable signature verification of update candidate and/or installed manifests.",
    )

    cmd_mpi_merge = cmd_mpi_subparsers.add_parser(
        MPI_MERGE,
        help="Merge Manifest Provisioning Information binaries into a single .HEX file, protected with SHA256",
    )
    cmd_mpi_merge.add_argument("--output-file", required=True, help="Output file path.")
    cmd_mpi_merge.add_argument(
        "--address",
        required=True,
        type=lambda x: int(x, 0),
        help="Address inside the internal memory of the MPI block, assigned to a single domain.",
    )
    cmd_mpi_merge.add_argument(
        "--size",
        required=True,
        type=lambda x: int(x, 0),
        help="Size of the memory, reserved for the MPI structures, assigned to a single domain.",
    )

    cmd_mpi_merge.add_argument(
        "--file",
        required=False,
        action="append",
        help="A single MPI configuration area to merge.",
    )


class MpiGenerator:
    """Class generating SUIT Manifest Provisioning Information."""

    BYTE_ORDER = "little"

    @staticmethod
    def generate(
        output_file: str,
        vendor_name: str,
        class_name: str,
        address: int,
        size: int,
        downgrade_prevention_enabled: bool,
        independent_updates: bool,
        signature_verification: str,
    ) -> None:
        """Generate HEX file for a single manifest role."""
        # Little endian,
        # SUIT MPI format:
        #   uint8_t for SUIT MPI format version
        #   uint8_t for downgrade prevention policy
        #   uint8_t for independent updateability policy
        #   uint8_t for signature verification policy
        #   12x uint8_t reserved for future use
        #   16x uint8_t for vendor UUID
        #   16x uint8_t for class UUID
        version = 1
        vid = uuid.uuid5(uuid.NAMESPACE_DNS, vendor_name)
        cid = uuid.uuid5(vid, class_name)

        if downgrade_prevention_enabled:
            downgrade_prevention_enabled_bytes = b"\02"
        else:
            downgrade_prevention_enabled_bytes = b"\01"

        if independent_updates:
            independent_updates_bytes = b"\02"
        else:
            independent_updates_bytes = b"\01"

        if signature_verification is None:
            signature_verification_bytes = b"\01"
        elif signature_verification == "update":
            signature_verification_bytes = b"\02"
        elif signature_verification == "update-and-boot":
            signature_verification_bytes = b"\03"
        else:
            raise GeneratorError(f"Unsupported signature verification policy: {signature_verification}")

        mpi = (
            version.to_bytes(1, MpiGenerator.BYTE_ORDER)
            + downgrade_prevention_enabled_bytes
            + independent_updates_bytes
            + signature_verification_bytes
            + b"\xFF" * 12  # Reserved for future use
            + vid.bytes
            + cid.bytes
        )

        mpi_hex = IntelHex()
        mpi_hex.frombytes(mpi.ljust(size, b"\xFF"), address)
        mpi_hex.write_hex_file(output_file)

    @staticmethod
    def merge(
        output_file: str,
        address: int,
        size: int,
        files: list[str],
    ) -> None:
        """Generate HEX file for an MPI area with it's digest, attached to a single domain."""
        merged_hex = IntelHex()

        if files is not None:
            for file in files:
                slot_hex = IntelHex(file)
                if (slot_hex.minaddr() < address) or (slot_hex.maxaddr() > address + size - 1):
                    raise GeneratorError(f"HEX file {file} outside of the mergeable area")
                merged_hex.merge(slot_hex)

        # Regenerate by filling all missing bytes with 0xFF
        merged_hex.padding = 0xFF
        merged_bin = merged_hex.tobinstr(start=address, end=address + size - 1)

        # Append SHA256 digest
        hash_func = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_func.update(merged_bin)
        hash_bin = hash_func.finalize()
        merged_bin += hash_bin

        # Export to the output file
        merged_hex = IntelHex()
        merged_hex.frombytes(merged_bin, address)
        merged_hex.write_hex_file(output_file)


def main(**kwargs) -> None:
    """Create Manifest Provisioning Information binary.

    :Keyword Arguments:
        * **output_file** - output file path
        * **address** - address inside the internal memory of the generated MPI structure
        * **size** - size of the memory, reserved for the MPI structure
        * **file** - a single MPI configuration area to merge
        * **vendor_name** - vendor name to use for UUID generation
        * **class_name** - device class name to use for UUID generation
        * **downgrade_prevention_enabled** - enable downgrade prevention policy
        * **independent_updates** - enable independent updateability
        * **signature_verification** - enable signature verification of update candidate and/or installed manifests
    """
    if kwargs["mpi"] == MPI_GENERATE:
        MpiGenerator.generate(
            kwargs["output_file"],
            kwargs["vendor_name"],
            kwargs["class_name"],
            kwargs["address"],
            kwargs["size"],
            kwargs["downgrade_prevention_enabled"],
            kwargs["independent_updates"],
            kwargs["signature_verification"],
        )
    elif kwargs["mpi"] == MPI_MERGE:
        MpiGenerator.merge(
            kwargs["output_file"],
            kwargs["address"],
            kwargs["size"],
            kwargs["file"],
        )
    else:
        raise GeneratorError(f"Invalid 'mpi' subcommand: {kwargs['mpi']}")
