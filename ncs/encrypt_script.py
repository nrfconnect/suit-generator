#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""
This script allows to output artifacts needed by a SUIT envelope for encrypted firmware.
"""

import os
import cbor2
from argparse import ArgumentParser
from argparse import RawTextHelpFormatter
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from enum import Enum, unique
from pynrfkms.kms import KMS
import getpass


@unique
class SuitAlgorithms(Enum):
    """Suit algorithms."""

    COSE_ALG_AES_GCM_128 = 1
    COSE_ALG_AES_GCM_192 = 2
    COSE_ALG_AES_GCM_256 = 3
    COSE_ALG_A128KW = -3
    COSE_ALG_A192KW = -4
    COSE_ALG_A256KW = -5


class SuitIds(Enum):
    """Suit elements identifiers."""

    COSE_ALG = 1
    COSE_KEY_ID = 4
    COSE_IV = 5


class SuitDomains(Enum):
    """Suit domains."""

    APPLICATION = "application"
    RADIO = "radio"
    CELL = "cell"
    WIFI = "wifi"

    def __str__(self):
        return self.value


class SuitDigestAlgorithms(Enum):
    """Suit digest algorithms."""

    SHA_256 = "sha-256"
    SHA_384 = "sha-384"
    SHA_512 = "sha-512"
    SHAKE128 = "shake128"
    SHAKE256 = "shake256"

    def __str__(self):
        return self.value


class EncryptionKMSBackends(Enum):
    """KMS backends."""

    VAULT = "vault"
    LOCAL = "local"

    def __str__(self):
        return self.value


KEY_IDS = {
    SuitDomains.APPLICATION.value: 0x40020200,
    SuitDomains.RADIO.value: 0x40030200,
    SuitDomains.CELL.value: 0x40040200,
    SuitDomains.WIFI.value: 0x40060200,
}


class DigestGenerator:

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
    kms = None

    def init_kms_backend(self, cli_arguments):
        if cli_arguments.kms_backend == EncryptionKMSBackends.VAULT:
            self.kms = KMS(backend="vault", url=cli_arguments.kms_vault_url, token=cli_arguments.kms_token)
        elif cli_arguments.kms_backend == EncryptionKMSBackends.LOCAL:
            pswd = cli_arguments.kms_local_password
            if pswd is None:
                pswd = getpass.getpass("Enter password for local KMS backend: ")
            self.kms = KMS(backend="local", dir=cli_arguments.kms_dir, password=pswd, encoding="der")
            del pswd

    def generate_kms_artifacts(self, plaintext_file_path: Path, key_name: str, context: str):
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

        encrypted_asset, encrypted_cek = self.kms.aes_key_wrap(
            key_name=key_name,
            context=context,
            plaintext=asset_plaintext,
            aek_type="aes",
            aad=enc_structure_encoded,
        )
        return encrypted_asset, encrypted_cek

    def parse_encrypted_assets(self, asset_bytes):
        init_vector = asset_bytes[:12]  # the names init vector and nonce are used interchangeably in this case
        # NOTE - it is not yet clear if this is a temporary bug or a difference in format,
        # but nrfkms wrap returns the encrypted data in format nonce|encrypted_data|tag, instead of nonce|tag|encrypted_data
        # which is returned by nrfkms encrypt
        encrypted_content = asset_bytes[12:-16]
        tag = asset_bytes[-16:]
        return init_vector, tag, encrypted_content

    def generate_encrypted_payload(self, encrypted_content, tag, output_directory: Path):
        with open(os.path.join(output_directory, "encrypted_content.bin"), "wb") as file:
            file.write(tag + encrypted_content)

    def generate_suit_encryption_info(self, iv, encrypted_cek, domain, output_directory: Path):

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
                        SuitIds.COSE_ALG.value: SuitAlgorithms.COSE_ALG_A256KW.value,
                        SuitIds.COSE_KEY_ID.value: cbor2.dumps(KEY_IDS[domain]),
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
        self, encrypted_asset: Path, encrypted_cek: Path, output_directory: Path, domain: str
    ):
        init_vector, tag, encrypted_content = self.parse_encrypted_assets(encrypted_asset)
        self.generate_encrypted_payload(encrypted_content, tag, output_directory)
        self.generate_suit_encryption_info(init_vector, encrypted_cek, domain, output_directory)


def create_encrypt_and_generate_subparser(top_parser):
    parser = top_parser.add_parser(
        "encrypt-and-generate", help="First encrypt the command using nrfkms, then generate the files."
    )

    parser.add_argument("--firmware", required=True, type=Path, help="Input, plaintext firmware.")
    parser.add_argument("--key-name", required=True, type=str, help="Name of the key used to derive the key by nrfkms.")
    parser.add_argument(
        "--domain",
        required=True,
        type=SuitDomains,
        choices=list(SuitDomains),
        help="The SoC domain of the firmware. Used to determine the key ID.",
    )
    parser.add_argument(
        "--context",
        required=True,
        type=str,
        help="Context string used to derive the key. See nrfkms documentation for more information.",
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
        "--kms-backend",
        required=True,
        type=EncryptionKMSBackends,
        choices=list(EncryptionKMSBackends),
        help="KMS backend to use.",
    )
    parser.add_argument("--kms-vault-url", type=str, help='URL of the KMS vault - only if kms-backend set to "vault".')
    parser.add_argument("--kms-token", type=str, help='KMS token - only if kms-backend set to "vault"')
    parser.add_argument("--kms-dir", type=str, help='Local backend directory - only if kms-backend set to "local".')
    parser.add_argument(
        "--kms-local-password",
        type=str,
        help='KMS local backend password - only if kms-backend set to "local". If not provided, the script will prompt for it.',
    )


def create_generate_subparser(top_parser):
    parser = top_parser.add_parser("generate", help="Only generate files based on encrypted firmware")

    parser.add_argument(
        "--encrypted-firmware",
        required=True,
        type=Path,
        help="Input, encrypted firmware in form iv|tag|encrypted_firmware",
    )
    parser.add_argument("--encrypted-key", required=True, type=Path, help="Encrypted content/asset encryption key")
    parser.add_argument(
        "--domain",
        required=True,
        type=SuitDomains,
        choices=list(SuitDomains),
        help="The SoC domain of the firmware. Used to determine the key ID.",
    )
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory to store the output files")


def create_subparsers(parser):
    subparsers = parser.add_subparsers(dest="command", required=True, help="Choose subcommand:")

    create_encrypt_and_generate_subparser(subparsers)
    create_generate_subparser(subparsers)


if __name__ == "__main__":
    parser = ArgumentParser(
        description="""This script allows to output artifacts needed by a SUIT envelope for encrypted firmware.

It has two modes of operation:
    - encrypt-and-generate: First encrypt the command using nrfkms, then generate the files.
    - generate: Only generate files based on encrypted firmware and the encrypted content/asset encryption key.
    Note the encrypted firmware should match the format generated by nrfkms iv|tag|encrypted_firmware.

In both cases the output files are:
    encrypted_content.bin - encrypted content of the firmware concatenated with the tag (encrypted firmware|16 byte tag).
                            This file is used as the payload in the SUIT envelope.
    suit_encryption_info.bin - The binary contents which should be included in the SUIT envelope as the contents of the suit-encryption-info parameter.

Additionally, the encrypt-and-generate mode generates the following file:
    plain_text_digest.bin - The digest of the plaintext firmware.
    plain_text_size.txt - The size of the plaintext firmware in bytes.
    """,
        formatter_class=RawTextHelpFormatter,
    )

    create_subparsers(parser)

    arguments = parser.parse_args()

    encrypted_asset = None
    encrypted_cek = None

    encryptor = Encryptor()

    if arguments.command == "encrypt-and-generate":
        encryptor.init_kms_backend(arguments)
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
        encrypted_asset, encrypted_cek, arguments.output_dir, arguments.domain.value
    )
