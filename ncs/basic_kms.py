#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""A basic KMS based on keys stored in files on the local drive."""

import os

from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from suit_generator.suit_kms_base import SuitKMSBase
import json


class SuitKMS(SuitKMSBase):
    """Implementation of the KMS."""

    def parse_context(self, context):
        """Parse the provided context string."""
        if context is None:
            self.keys_directory = Path(__file__).parent
            return None

        # Check if context is a valid path
        context_path = Path(context)
        if context_path.is_dir():
            self.keys_directory = context_path
            return

        try:
            context_loaded = json.loads(context)
        except json.JSONDecodeError:
            raise ValueError(f"The provided context '{context}' is neither a valid path nor a valid JSON string.")

        try:
            self.keys_directory = Path(context_loaded["keys_directory"])
        except KeyError:
            raise ValueError(f"The provided json context '{context}' does not contain the 'keys_directory' key.")

    def init_kms(self, context) -> None:
        """
        Initialize the KMS.

        :param context: The context to be used
        """
        self.parse_context(context)

    def encrypt(self, plaintext, key_name, context, aad) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt the plaintext with an AES key.

        :param plaintext: The plaintext to be encrypted.
        :param key_name: The name of the key to be used.
        :param context: The context to be used
                        If it is passed, it is used to point to the directory where the keys are stored.
                        It can either be a path or a JSON string in the format '{ "keys_directory":"<path>" }'.
        :param aad: The additional authenticated data to be used.
        :return: The nonce, tag and ciphertext.
        :rtype: tuple[bytes, bytes, bytes]
        """
        key_file_name = key_name + ".bin"
        key_file = self.keys_directory / key_file_name

        with open(key_file, "rb") as f:
            key_data = f.read()
        aesgcm = AESGCM(key_data)
        nonce = os.urandom(12)
        ciphertext_response = aesgcm.encrypt(nonce, plaintext, aad)
        ciphertext = ciphertext_response[:-16]
        tag = ciphertext_response[-16:]

        return nonce, tag, ciphertext


def suit_kms_factory():
    """Get a KMS object."""
    return SuitKMS()
