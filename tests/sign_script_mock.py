#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Script mocking the Sign script."""
from __future__ import annotations
from suit_generator.suit_sign_script_base import (
    SuitEnvelopeSignerBase,
    SignatureAlreadyPresentActions,
    SuitSignAlgorithms,
)
import cbor2
import json
from pathlib import Path
from enum import Enum


class SuitIds(Enum):
    """Suit elements identifiers."""

    SUIT_AUTHENTICATION_WRAPPER = 2


class SignerMock(SuitEnvelopeSignerBase):
    """Signer mock implementation."""

    def mock_add_signature(self, mocked_signature: bytes) -> None:
        """Add signature object to the envelope."""
        data = [cbor2.dumps({}), {}, None, mocked_signature]
        new_auth = cbor2.CBORTag(18, data)
        auth_block = cbor2.loads(self.envelope.value[SuitIds.SUIT_AUTHENTICATION_WRAPPER.value])
        auth_block.append(cbor2.dumps(new_auth))
        self.envelope.value[SuitIds.SUIT_AUTHENTICATION_WRAPPER.value] = cbor2.dumps(auth_block)

    def sign_envelope(
        self,
        input_envelope: cbor2.CBORTag,
        key_name: str,
        key_id: int,
        algorithm: SuitSignAlgorithms,
        context: str,
        kms_script: Path,
        already_signed_action: SignatureAlreadyPresentActions,
    ) -> cbor2.CBORTag:
        """Mock adding signature to the envelope."""
        context_loaded = json.loads(context)
        self.output_file = f"test_output_{key_name}.json"
        self.json_data = {"key_name": key_name}
        self.json_data["key_id"] = key_id
        self.json_data["algorithm"] = algorithm.value
        self.json_data["context"] = context_loaded["ctx"]
        self.json_data["kms_script"] = kms_script
        self.json_data["already_signed_action"] = already_signed_action.value
        with open(self.output_file, "w") as f:
            json.dump(self.json_data, f)

        self.envelope = input_envelope
        self.mock_add_signature(context_loaded["signature"].encode())
        return self.envelope


def suit_signer_factory():
    """Get a Signer object."""
    return SignerMock()
