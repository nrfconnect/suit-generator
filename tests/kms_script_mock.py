#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Script mocking the KMS script."""
from __future__ import annotations

from suit_generator.suit_kms_base import SuitKMSBase
import json


class SuitMockKMS(SuitKMSBase):
    """Implementation mocking a KMS."""

    def init_kms(self, context: str) -> None:
        """
        Initialize the KMS.

        :param context: The context to be used - json string with keys {"output_file": "<path>", "ctx": "<ctx>"}

        For signing mocking it also has to contain a "signature" key with the mocked signature to be returned.
        For encryption mocking it also has to contain "iv", "encryption_key" and "encrypted_data" keys
        with the mocked values to be returned.
        All the data will be stored into the file pointed by the output_file key.

        """
        context_loaded = json.loads(context)
        self.output_file = context_loaded["output_file"]
        self.json_data = {"init_kms_ctx": context_loaded["ctx"]}

    def encrypt(self, plaintext: bytes, key_name: str, context: str, aad: bytes) -> tuple[bytes, bytes, bytes]:
        """Mock of the KMS script encrypt function."""
        context_loaded = json.loads(context)
        self.json_data["encrypt_plaintext"] = plaintext.decode()
        self.json_data["encrypt_key_name"] = key_name
        self.json_data["encrypt_context"] = context_loaded["ctx"]
        self.json_data["encrypt_aad"] = aad.decode()
        with open(self.output_file, "w") as f:
            json.dump(self.json_data, f)
        return (
            context_loaded["iv"].encode(),
            context_loaded["encryption_key"].encode(),
            context_loaded["encrypted_data"].encode(),
        )

    def sign(self, data: bytes, key_name: str, algorithm: str, context: str) -> bytes:
        """Mock of the KMS script sign function."""
        context_loaded = json.loads(context)
        self.json_data["sign_data"] = data.hex()
        self.json_data["sign_key_name"] = key_name
        self.json_data["sign_algorithm"] = algorithm
        self.json_data["sign_context"] = context_loaded["ctx"]
        with open(self.output_file, "w") as f:
            json.dump(self.json_data, f)
        return context_loaded["signature"].encode()


def suit_kms_factory():
    """Get a KMS object."""
    return SuitMockKMS()
