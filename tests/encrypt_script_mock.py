#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Script mocking the Encrypt script."""
import json

from pathlib import Path
from suit_generator.suit_encrypt_script_base import (
    SuitEncryptorBase,
    SuitDigestAlgorithms,
    SuitKWAlgorithms,
)


class EncryptorMock(SuitEncryptorBase):
    """Encryptor mock implementation."""

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
        """Mock encrypting the payload and generation of encryption artifacts."""
        context_loaded = json.loads(context)
        self.output_file = f"test_output_{key_name}.json"
        self.json_data = {"firmware": firmware.hex()}
        self.json_data["key_name"] = key_name
        self.json_data["key_id"] = key_id
        self.json_data["kw_alg"] = kw_alg.value
        self.json_data["hash_alg"] = hash_alg.value
        self.json_data["context"] = context_loaded["ctx"]
        self.json_data["kms_script"] = kms_script
        with open(self.output_file, "w") as f:
            json.dump(self.json_data, f)

        return (
            bytes.fromhex(context_loaded["encrypted_data"]),
            bytes.fromhex(context_loaded["tag"]),
            bytes.fromhex(context_loaded["encryption_info"]),
            bytes.fromhex(context_loaded["digest"]),
            context_loaded["plaintext_length"],
        )

    def generate(
        self, encrypted_asset: bytes, encrypted_cek: bytes, key_id: int, kw_alg: SuitKWAlgorithms
    ) -> tuple[bytes, bytes, bytes]:
        """
        Mock generation of encryption artifacts.

        The encrypted asset for this mock is a json object, containing the return values.
        """
        #         :return: The encrypted payload, tag, encryption info.
        context_loaded = json.loads(encrypted_asset.decode())
        self.output_file = f"test_output_{key_id}.json"

        self.json_data = {"key_id": key_id}
        self.json_data["kw_alg"] = kw_alg.value
        self.json_data["encrypted_cek"] = encrypted_cek.hex()
        with open(self.output_file, "w") as f:
            json.dump(self.json_data, f)

        return (
            bytes.fromhex(context_loaded["encrypted_data"]),
            bytes.fromhex(context_loaded["tag"]),
            bytes.fromhex(context_loaded["encryption_info"]),
        )


def suit_encryptor_factory():
    """Get an Encryptor object."""
    return EncryptorMock()
