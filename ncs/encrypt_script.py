#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Script to create artifacts needed by a SUIT envelope for encrypted firmware."""

import cbor2
import importlib.util
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from enum import Enum, unique
from suit_generator.suit_kms_base import SuitKMSBase
from suit_generator.suit_encrypt_script_base import (
    SuitEncryptorBase,
    SuitDigestAlgorithms,
    SuitKWAlgorithms,
)


@unique
class SuitCoseEncryptAlgorithms(Enum):
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


def _import_module_from_path(module_name, file_path):
    """Import a python module from a file path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class DigestGenerator:
    """Class to generate digests for plaintext using specified hash algorithms."""

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

    def generate_digest_size_for_plain_text(self, plaintext: bytes):
        """Generate digest and return the size of the given plaintext."""
        func = hashes.Hash(self._hash_func[self._hash_name], backend=default_backend())
        func.update(plaintext)
        digest = func.finalize()
        return digest, len(plaintext)


class Encryptor(SuitEncryptorBase):
    """Class to handle encryption operations using specified key wrap algorithms."""

    kms = None

    def init_kms_backend(self, kms_script: Path, context: str) -> None:
        """Initialize the KMS from the provided script backend based on the passed context."""
        module_name = "SuitKMS_module"
        kms_module = _import_module_from_path(module_name, kms_script)
        if not hasattr(kms_module, "suit_kms_factory"):
            raise ValueError(f"Python script {kms_script} does not contain the required suit_kms_factory function")
        self.kms = kms_module.suit_kms_factory()
        if not isinstance(self.kms, SuitKMSBase):
            raise ValueError(f"Class {type(self.kms)} does not implement the required SuitKMSBase interface")
        self.kms.init_kms(context)

    def generate_kms_artifacts(self, asset_plaintext: bytes, key_name: str, context: str) -> tuple[bytes, bytes]:
        """Generate encrypted artifacts using the key management system.

        This method encrypts asset_plaintext bytes using the specified key wrap algorithm,
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

        nonce = None
        tag = None
        ciphertext = None
        encrypted_cek = None

        if self.cose_kw_alg == SuitCoseEncryptAlgorithms.COSE_ALG_A256KW.value:
            raise ValueError("AES Key Wrap 256 is not supported yet")
        elif self.cose_kw_alg == SuitCoseEncryptAlgorithms.COSE_ALG_DIRECT.value:
            nonce, tag, ciphertext = self.kms.encrypt(
                plaintext=asset_plaintext,
                key_name=key_name,
                context=context,
                aad=enc_structure_encoded,
            )

        encrypted_asset = nonce + tag + ciphertext

        return encrypted_asset, encrypted_cek

    def parse_encrypted_assets(self, asset_bytes: bytes) -> tuple[bytes, bytes, bytes]:
        """Parse the encrypted assets to extract initialization vector, tag, and encrypted content."""
        # Encrypted data is returned in format nonce|tag|encrypted_data
        init_vector = asset_bytes[:12]
        tag = asset_bytes[12 : 12 + 16]
        encrypted_content = asset_bytes[12 + 16 :]

        return init_vector, tag, encrypted_content

    def generate_encrypted_payload(self, encrypted_content: bytes, tag: bytes) -> bytes:
        """Generate the encrypted payload.

        This method returns the encrypted payload consisting of the encrypted content and the authentication tag.
        """
        return tag + encrypted_content

    def generate_suit_encryption_info(self, iv: bytes, encrypted_cek: bytes, key_id: int) -> bytes:
        """Generate the SUIT encryption information.

        This method creates a CBOR-encoded SUIT encryption information structure.
        """
        Cose_Encrypt = [
            # protected
            cbor2.dumps(
                {
                    SuitIds.COSE_ALG.value: SuitCoseEncryptAlgorithms.COSE_ALG_AES_GCM_256.value,
                }
            ),
            # unprotected
            {
                SuitIds.COSE_IV.value: iv,
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
                        SuitIds.COSE_KEY_ID.value: cbor2.dumps(key_id),
                    },
                    # ciphertext
                    encrypted_cek,
                ]
            ],
        ]

        Cose_Encrypt_Tagged = cbor2.CBORTag(96, Cose_Encrypt)
        encryption_info = cbor2.dumps(cbor2.dumps(Cose_Encrypt_Tagged))

        return encryption_info

    def generate_encryption_info_and_encrypted_payload(
        self, encrypted_asset: bytes, encrypted_cek, key_id: int
    ) -> tuple[bytes, bytes, bytes]:
        """Generate encryption information and encrypted payload.

        This method parses the encrypted asset to extract the initialization vector, tag, and encrypted content.
        It then generates the encrypted payload and the SUIT encryption information.
        """
        init_vector, tag, encrypted_content = self.parse_encrypted_assets(encrypted_asset)
        encryption_info = self.generate_suit_encryption_info(init_vector, encrypted_cek, key_id)
        return encrypted_content, tag, encryption_info

    def _kw_alg_convert(self, kw_alg: SuitKWAlgorithms) -> None:
        if kw_alg == SuitKWAlgorithms.A256KW:
            self.cose_kw_alg = SuitCoseEncryptAlgorithms.COSE_ALG_A256KW.value
        else:
            self.cose_kw_alg = SuitCoseEncryptAlgorithms.COSE_ALG_DIRECT.value

    def encrypt_and_generate(
        self,
        firmware: bytes,
        key_name: str,
        key_id: int,
        context: str,
        hash_alg: SuitDigestAlgorithms,
        kw_alg: SuitKWAlgorithms,
        kms_script: Path,
    ) -> tuple[bytes, bytes, bytes, bytes, int]:
        """
        Encrypt the payload and return the encryption artifacts.

        :param firmware: The plaintext firmware.
        :param key_name: The name of the key used by the KMS to identify the key.
        :param key_id: The key ID used to identify the key on the device.
        :param context: Any context information that should be passed to the KMS backend during initialization
                        and encryption.
        :param hash_alg: The algorithm used to create plaintext digest.
        :param kw_alg: Key wrap algorithm used to wrap the CEK.
        :param kms_script: Python script containing a SuitKMS class with an encrypt function - used to communicate
                           with a KMS.

        :return: The encrypted payload, tag, encryption info, digest, and plaintext length.
        :rtype: tuple[bytes, bytes, bytes, bytes, int]
        """
        self._kw_alg_convert(kw_alg)
        self.init_kms_backend(kms_script, context)

        digest_generator = DigestGenerator(hash_alg.value)
        digest, plaintext_len = digest_generator.generate_digest_size_for_plain_text(firmware)
        encrypted_asset, encrypted_cek = self.generate_kms_artifacts(firmware, key_name, context)
        encrypted_payload, tag, encryption_info = self.generate_encryption_info_and_encrypted_payload(
            encrypted_asset, encrypted_cek, key_id
        )
        return encrypted_payload, tag, encryption_info, digest, plaintext_len

    def generate(
        self, encrypted_asset: bytes, encrypted_cek: bytes, key_id: int, kw_alg: SuitKWAlgorithms
    ) -> tuple[bytes, bytes, bytes]:
        """
        Generate encryption artifacts on encrypted firmware and the encrypted content/asset encryption key.

        :param encrypted_asset: The encrypted firmware in form iv|tag|encrypted_firmware.
        :param encrypted_cek: The encrypted content/asset encryption key.
        :param key_id: The key ID used to identify the key on the device.
        :param kw_alg: Key wrap algorithm used to wrap the CEK.

        :return: The encrypted payload, tag, encryption info.
        :rtype: tuple[bytes, bytes, bytes]
        """
        if kw_alg == SuitKWAlgorithms.A256KW:
            if encrypted_cek is None:
                raise ValueError("Encrypted CEK is required for AES Key Wrap 256")
        self._kw_alg_convert(kw_alg)
        return self.generate_encryption_info_and_encrypted_payload(encrypted_asset, encrypted_cek, key_id)


def suit_encryptor_factory():
    """Get an Encryptor object."""
    return Encryptor()
