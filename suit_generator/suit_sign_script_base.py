#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""A base abstract class for any SUIT sign script implementations."""

import cbor2
from abc import ABC, abstractmethod
from enum import Enum, unique
from pathlib import Path


@unique
class SuitSignAlgorithms(Enum):
    """Suit signing algorithms."""

    ES_256 = "es-256"
    ES_384 = "es-384"
    ES_521 = "es-521"
    EdDSA = "eddsa"
    VS_HashEdDSA = "hash-eddsa"

    def __str__(self):
        return self.value


class SignatureAlreadyPresentActions(Enum):
    """Action to take when a signature is already present in the envelope."""

    ERROR = "error"
    REMOVE_OLD = "remove-old"
    SKIP = "skip"
    APPEND = "append"

    def __str__(self):
        return self.value


class SuitEnvelopeSignerBase(ABC):
    """Base abstract class for the Signer implementations."""

    @abstractmethod
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
        """
        Add signature to the envelope.

        :param input_envelope: The input envelope to sign.
        :param key_name: The name of the key used by the KMS to identify the key.
        :param key_id: The key ID used to identify the key on the device.
        :param algorithm: The algorithm used to sign the envelope.
        :param context: Any context information that should be passed to the KMS backend during initialization
                        and signing.
        :param kms_script: Python script containing a SuitKMS class with a sign function - used to communicate
                           with a KMS.
        :param already_signed_action: Action to take when a signature is already present in the envelope.

        :return: The signed envelope.
        :rtype: bytes
        """
        pass
