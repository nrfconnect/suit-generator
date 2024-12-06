#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""A base abstract class for any KMS implementations used by the SUIT encrypt/sign scripts."""

from abc import ABC, abstractmethod


class SuitKMSBase(ABC):
    """Base abstract class for the KMS implementations."""

    @abstractmethod
    def init_kms(self, context) -> None:
        """
        Initialize the KMS.

        :param context: The context to be used
        """
        pass

    @abstractmethod
    def encrypt(self, plaintext, key_name, context, aad) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt the plainext with an AES key.

        :param plaintext: The plaintext to be encrypted.
        :param key_name: The name of the key to be used.
        :param context: The context to be used
        :param aad: The additional authenticated data to be used.
        :return: The nonce, tag and ciphertext.
        :rtype: tuple[bytes, bytes, bytes]
        """
        pass
