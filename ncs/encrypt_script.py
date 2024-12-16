#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Script to create artifacts needed by a SUIT envelope for encrypted firmware."""

import os
import cbor2
import importlib.util
import sys
from argparse import ArgumentParser
from argparse import RawTextHelpFormatter
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from enum import Enum, unique
from suit_generator.suit_kms_base import SuitKMSBase


@unique
class SuitAlgorithms(Enum):
    """Suit algorithms."""

    COSE_ALG_AES_GCM_128 = 1
    COSE_ALG_AES_GCM_192 = 2
    COSE_ALG_AES_GCM_256 = 3
    COSE_ALG_A128KW = -3
    COSE_ALG_A192KW = -4
    COSE_ALG_A256KW = -5
    COSE_ALG_DIRECT = -6


class SuitIds(Enum):
    """Suit elements identifiers."""

    COSE_ALG = 1
    COSE_KEY_ID = 4
    COSE_IV = 5


class SuitDigestAlgorithms(Enum):
    """Suit digest algorithms."""

    SHA_256 = "sha-256"
    SHA_384 = "sha-384"
    SHA_512 = "sha-512"
    SHAKE128 = "shake128"
    SHAKE256 = "shake256"

    def __str__(self):
        return self.value


class SuitKWAlgorithms(Enum):
    """Supported SUIT Key wrap/derivation algorithms."""

    A256KW = "aes-kw-256"
    DIRECT = "direct"

    def __str__(self):
        return self.value


KEY_IDS = {
    "FWENC_APPLICATION_GEN1": 0x40022000,
    "FWENC_APPLICATION_GEN2": 0x40022001,
    "FWENC_RADIOCORE_GEN1": 0x40032000,
    "FWENC_RADIOCORE_GEN2": 0x40032001,
    "FWENC_CELL_GEN1": 0x40042000,
    "FWENC_CELL_GEN2": 0x40042001,
    "FWENC_WIFICORE_GEN1": 0x40062000,
    "FWENC_WIFICORE_GEN2": 0x40062001,
}


def _import_module_from_path(module_name, file_path):
    # Helper function to import a python module from a file path.
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class DigestGenerator:
    """Class to generate digests for plaintext files using specified hash algorithms."""

    _hash_func = {
        SuitDigestAlgorithms.SHA_256.value: hashes.SHA256(),
        SuitDigestAlgorithms.SHAKE128.value: hashes.SHAKE128(16),
        SuitDigestAlgorithms.SHA_384.value: hashes.SHA384(),
        SuitDigestAlgorithms.SHA_512.value: hashes.SHA512(),
        SuitDigestAlgorithms.SHAKE256.value: hashes.SHAKE256(32),
    }

    def __init__(self, hash_name: str):
        """Initialize object."""
        if hash_name not in self._hash_func:
            raise ValueError(f"Unsupported hash algorithm: {hash_name}")
        self._hash_name = hash_name

    def generate_digest_size_for_plain_text(self, plaintext_file_path: Path, output_directory: Path):
        """Class to generate digests for plaintext files using specified hash algorithms."""
        plaintext = []
        with open(plaintext_file_path, "rb") as plaintext_file:
            plaintext = plaintext_file.read()

        func = hashes.Hash(self._hash_func[self._hash_name], backend=default_backend())
        func.update(plaintext)
        digest = func.finalize()
        with open(os.path.join(output_directory, "plain_text_digest.bin"), "wb") as file:
            file.write(digest)
        with open(os.path.join(output_directory, "plain_text_size.txt"), "w") as file:
            file.write(str(len(plaintext)))


class Encryptor:
    """Class to handle encryption operations using specified key wrap algorithms."""

    kms = None

    def __init__(self, kw_alg: SuitKWAlgorithms):
        """Initialize the Encryptor with a specified key wrap algorithm."""
        if kw_alg == SuitKWAlgorithms.A256KW:
            self.cose_kw_alg = SuitAlgorithms.COSE_ALG_A256KW.value
        else:
            self.cose_kw_alg = SuitAlgorithms.COSE_ALG_DIRECT.value
        pass

    def init_kms_backend(self, kms_script, context):
        """Initialize the KMS from the provided script backend based on the passed context."""
        module_name = "SuitKMS_module"
        kms_module = _import_module_from_path(module_name, kms_script)
        self.kms = kms_module.suit_kms_factory()
        if not isinstance(self.kms, SuitKMSBase):
            raise ValueError(f"Class {type(self.kms)} does not implement the required SuitKMSBase interface")
        self.kms.init_kms(context)

    def generate_kms_artifacts(self, plaintext_file_path: Path, key_name: str, context: str):
        """Generate encrypted artifacts using the key management system.

        This method reads the plaintext file, encrypts it using the specified key wrap algorithm,
        and returns the encrypted asset and encrypted content encryption key (CEK).

        """
        # Enc structure:
        # {
        #         "context": "Encrypt",
        #         "protected": {"suit-cose-algorithm-id": "cose-alg-aes-gcm-256"},
        #         "external_aad": "",
        # }
        # bytes(hex): 8367456e637279707443a1010340
        enc_structure_encoded = bytes(
            [0x83, 0x67, 0x45, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x43, 0xA1, 0x01, 0x03, 0x40]
        )

        asset_plaintext = []
        with open(plaintext_file_path, "rb") as plaintext_file:
            asset_plaintext = plaintext_file.read()

        nonce = None
        tag = None
        ciphertext = None
        encrypted_cek = None

        if self.cose_kw_alg == SuitAlgorithms.COSE_ALG_A256KW.value:
            raise ValueError("AES Key Wrap 256 is not supported yet")
        elif self.cose_kw_alg == SuitAlgorithms.COSE_ALG_DIRECT.value:
            nonce, tag, ciphertext = self.kms.encrypt(
                plaintext=asset_plaintext,
                key_name=key_name,
                context=context,
                aad=enc_structure_encoded,
            )

        encrypted_asset = nonce + tag + ciphertext

        return encrypted_asset, encrypted_cek

    def parse_encrypted_assets(self, asset_bytes):
        """Parse the encrypted assets to extract initialization vector, tag, and encrypted content."""
        # Encrypted data is returned in format nonce|tag|encrypted_data
        init_vector = asset_bytes[:12]
        tag = asset_bytes[12 : 12 + 16]
        encrypted_content = asset_bytes[12 + 16 :]

        return init_vector, tag, encrypted_content

    def generate_encrypted_payload(self, encrypted_content, tag, output_directory: Path):
        """Generate the encrypted payload file.

        This method writes the encrypted content and authentication tag to a binary file.
        """
        with open(os.path.join(output_directory, "encrypted_content.bin"), "wb") as file:
            file.write(tag + encrypted_content)

    def generate_suit_encryption_info(self, iv, encrypted_cek, string_key_id, output_directory: Path):
        """Generate the SUIT encryption information file.

        This method creates a CBOR-encoded SUIT encryption information structure and writes it to a binary file.
        """
        Cose_Encrypt = [
            # protected
            cbor2.dumps(
                {
                    SuitIds.COSE_ALG.value: SuitAlgorithms.COSE_ALG_AES_GCM_256.value,
                }
            ),
            # unprotected
            {
                SuitIds.COSE_IV.value: bytes(iv),
            },
            # ciphertext
            None,
            # recipients
            [
                [
                    # protected
                    b"",
                    # unprotected
                    {
                        SuitIds.COSE_ALG.value: self.cose_kw_alg,
                        SuitIds.COSE_KEY_ID.value: cbor2.dumps(KEY_IDS[string_key_id]),
                    },
                    # ciphertext
                    encrypted_cek,
                ]
            ],
        ]

        Cose_Encrypt_Tagged = cbor2.CBORTag(96, Cose_Encrypt)
        encryption_info = cbor2.dumps(cbor2.dumps(Cose_Encrypt_Tagged))

        with open(os.path.join(output_directory, "suit_encryption_info.bin"), "wb") as file:
            file.write(encryption_info)

    def generate_encryption_info_and_encrypted_payload(
        self, encrypted_asset: Path, encrypted_cek: Path, output_directory: Path, string_key_id: str
    ):
        """Generate encryption information and encrypted payload files.

        This method parses the encrypted asset to extract the initialization vector, tag, and encrypted content.
        It then generates the encrypted payload file and the SUIT encryption information file.
        """
        init_vector, tag, encrypted_content = self.parse_encrypted_assets(encrypted_asset)
        self.generate_encrypted_payload(encrypted_content, tag, output_directory)
        self.generate_suit_encryption_info(init_vector, encrypted_cek, string_key_id, output_directory)


def create_encrypt_and_generate_subparser(top_parser):
    """Create a subparser for the 'encrypt-and-generate' command."""
    parser = top_parser.add_parser("encrypt-and-generate", help="First encrypt the payload, then generate the files.")

    parser.add_argument("--firmware", required=True, type=Path, help="Input, plaintext firmware.")
    parser.add_argument(
        "--key-name", required=True, type=str, help="Name of the key used by the KMS to identify the key."
    )
    parser.add_argument(
        "--string-key-id",
        required=True,
        type=str,
        choices=KEY_IDS.keys(),
        metavar="STRING_KEY_ID",
        help="The string key ID used to identify the key on the device - translated to a numeric KEY ID.",
    )
    parser.add_argument(
        "--context",
        type=str,
        help="Any context information that should be passed to the KMS backend during initialization and encryption.",
    )
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory to store the output files")
    parser.add_argument(
        "--hash-alg",
        default=SuitDigestAlgorithms.SHA_256.value,
        type=SuitDigestAlgorithms,
        choices=list(SuitDigestAlgorithms),
        help="Algorithm used to create plaintext digest.",
    )
    parser.add_argument(
        "--kw-alg",
        default=SuitKWAlgorithms.DIRECT.value,
        type=SuitKWAlgorithms,
        choices=list(SuitKWAlgorithms),
        help="Key wrap algorithm used to wrap the CEK.",
    )
    parser.add_argument(
        "--kms-script",
        default=Path(__file__).parent / "basic_kms.py",
        help="Python script containing a SuitKMS class with an encrypt function - used to communicate with a KMS.",
    )


def create_generate_subparser(top_parser):
    """Create a subparser for the 'generate' command."""
    parser = top_parser.add_parser("generate", help="Only generate files based on encrypted firmware")

    parser.add_argument(
        "--encrypted-firmware",
        required=True,
        type=Path,
        help="Input, encrypted firmware in form iv|tag|encrypted_firmware",
    )
    parser.add_argument("--encrypted-key", required=True, type=Path, help="Encrypted content/asset encryption key")
    parser.add_argument(
        "--string-key-id",
        required=True,
        type=str,
        choices=KEY_IDS.keys(),
        help="The string key ID used to identify the key on the device - translated to a numeric KEY ID.",
    )
    parser.add_argument(
        "--kw-alg",
        default=SuitKWAlgorithms.DIRECT.value,
        type=SuitKWAlgorithms,
        choices=list(SuitKWAlgorithms),
        help="Key wrap algorithm used to wrap the CEK.",
    )
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory to store the output files")


def create_subparsers(parser):
    """Create subparsers for the main parser.

    This function adds subparsers for different commands to the main parser.
    """
    subparsers = parser.add_subparsers(dest="command", required=True, help="Choose subcommand:")

    create_encrypt_and_generate_subparser(subparsers)
    create_generate_subparser(subparsers)


if __name__ == "__main__":
    parser = ArgumentParser(
        description="""This script allows to output artifacts needed by a SUIT envelope for encrypted firmware.

It has two modes of operation:
    - encrypt-and-generate: First encrypt the payload, then generate the files.
    - generate: Only generate files based on encrypted firmware and the encrypted content/asset encryption key.
    Note the encrypted firmware should match the format iv|tag|encrypted_firmware

In both cases the output files are:
    encrypted_content.bin - encrypted content of the firmware concatenated with the tag (encrypted firmware|16 byte tag).
                            This file is used as the payload in the SUIT envelope.
    suit_encryption_info.bin - The binary contents which should be included in the SUIT envelope as the contents of the suit-encryption-info parameter.

Additionally, the encrypt-and-generate mode generates the following file:
    plain_text_digest.bin - The digest of the plaintext firmware.
    plain_text_size.txt - The size of the plaintext firmware in bytes.
    """,  # noqa: W291, E501
        formatter_class=RawTextHelpFormatter,
    )

    create_subparsers(parser)

    arguments = parser.parse_args()

    encrypted_asset = None
    encrypted_cek = None

    encryptor = Encryptor(arguments.kw_alg)

    if arguments.command == "encrypt-and-generate":
        encryptor.init_kms_backend(arguments.kms_script, arguments.context)
        digest_generator = DigestGenerator(arguments.hash_alg.value)
        digest_generator.generate_digest_size_for_plain_text(arguments.firmware, arguments.output_dir)
        encrypted_asset, encrypted_cek = encryptor.generate_kms_artifacts(
            arguments.firmware, arguments.key_name, arguments.context
        )

    if arguments.command == "generate":
        with open(arguments.encrypted_firmware, "rb") as file:
            encrypted_asset = file.read()
        with open(arguments.encrypted_key, "rb") as file:
            encrypted_cek = file.read()

    encryptor.generate_encryption_info_and_encrypted_payload(
        encrypted_asset, encrypted_cek, arguments.output_dir, arguments.string_key_id
    )
