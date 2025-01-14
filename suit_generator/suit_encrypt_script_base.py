#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""A base abstract class for any SUIT sign script implementations."""

from abc import ABC, abstractmethod
from enum import Enum, unique
from pathlib import Path


@unique
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


class SuitEncryptorBase(ABC):
    """Base abstract class for the Encryptor implementations."""

    @abstractmethod
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
        Encrypt the payload and generate the files.

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
        pass

    @abstractmethod
    def generate(
        self, encrypted_asset: bytes, encrypted_cek: bytes, key_id: int, kw_alg: SuitKWAlgorithms
    ) -> tuple[bytes, bytes, bytes]:
        """
        Generate files based on encrypted firmware and the encrypted content/asset encryption key.

        :param encrypted_asset: The encrypted firmware in form iv|tag|encrypted_firmware.
        :param encrypted_cek: The encrypted content/asset encryption key.
        :param key_id: The key ID used to identify the key on the device.
        :param kw_alg: Key wrap algorithm used to wrap the CEK.

        :return: The encrypted payload, tag, encryption info.
        :rtype: tuple[bytes, bytes, bytes]
        """
        pass
