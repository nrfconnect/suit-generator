#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""DO NOT USE in the production environment - this is an example script.

It is highly NOT recommended to store private keys on the local machines.

The script is available only to present the process of envelope signing
and can be used as a base to integrate external Key Management System with the NCS build system.

It is highly recommended to execute signing only in the secure environment.
"""
from __future__ import annotations

import cbor2
import importlib.util
import sys

from pathlib import Path
from enum import Enum, unique
from suit_generator.suit_kms_base import SuitKMSBase
from suit_generator.suit_sign_script_base import (
    SuitEnvelopeSignerBase,
    SignatureAlreadyPresentActions,
    SuitSignAlgorithms,
)


@unique
class SuitCoseSignAlgorithms(Enum):
    """Suit algorithms."""

    COSE_ALG_ES_256 = -7
    COSE_ALG_ES_384 = -35
    COSE_ALG_ES_521 = -36
    COSE_ALG_EdDSA = -8
    COSE_ALG_VS_HashedEdDSA = -65537


class SuitIds(Enum):
    """Suit elements identifiers."""

    COSE_ALG = 1
    COSE_KEY_ID = 4
    SUIT_MANIFEST = 3
    SUIT_AUTHENTICATION_WRAPPER = 2
    SUIT_MANIFEST_COMPONENT_ID = 5


class SignerError(Exception):
    """Signer exception."""


def _import_module_from_path(module_name: str, file_path: Path):
    """Import a python module from a file path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class Signer(SuitEnvelopeSignerBase):
    """Signer implementation."""

    def init_kms_backend(self, kms_script: Path):
        """Initialize the KMS from the provided script backend based on the passed context."""
        module_name = "SuitKMS_module"
        kms_module = _import_module_from_path(module_name, kms_script)
        if not hasattr(kms_module, "suit_kms_factory"):
            raise ValueError(f"Python script {kms_script} does not contain the required suit_kms_factory function")
        self.kms = kms_module.suit_kms_factory()
        if not isinstance(self.kms, SuitKMSBase):
            raise ValueError(f"Class {type(self.kms)} does not implement the required SuitKMSBase interface")
        self.kms.init_kms(self._context)

    @staticmethod
    def create_authentication_block(protected: dict | None, unprotected: dict | None, signature: bytes):
        """Create Authentication Block."""
        data = [cbor2.dumps(protected), unprotected if unprotected is not None else {}, None, signature]
        auth_block = cbor2.CBORTag(18, data)
        return auth_block

    def create_cose_structure(self, protected: dict) -> bytes:
        """Create COSE Sig_structure."""
        data = ["Signature1", cbor2.dumps(protected), b"", cbor2.dumps(self.get_digest())]
        return cbor2.dumps(data)

    def get_digest(self) -> bytes:
        """Return digest object."""
        auth_block = cbor2.loads(self.envelope.value[SuitIds.SUIT_AUTHENTICATION_WRAPPER.value])
        digest = cbor2.loads(auth_block[0])
        return digest

    def already_signed_action(self, action: SignatureAlreadyPresentActions):
        """Check if the envelope is already signed - if it is, handle this case."""
        auth_block = cbor2.loads(self.envelope.value[SuitIds.SUIT_AUTHENTICATION_WRAPPER.value])
        for auth in auth_block:
            if not isinstance(auth, bytes):
                continue
            auth_deserialized = cbor2.loads(auth)
            if isinstance(auth_deserialized, cbor2.CBORTag) and auth_deserialized.tag == 18:
                if action == SignatureAlreadyPresentActions.ERROR:
                    raise SignerError("The envelope has already been signed and already-signed-action is set to error.")
                elif action == SignatureAlreadyPresentActions.REMOVE_OLD:
                    auth_block.remove(auth)
                    self.envelope.value[SuitIds.SUIT_AUTHENTICATION_WRAPPER.value] = cbor2.dumps(auth_block)
                elif action == SignatureAlreadyPresentActions.SKIP:
                    self._skip_signing = True
                    pass
                elif action == SignatureAlreadyPresentActions.APPEND:
                    raise NotImplementedError("Append signature action is not implemented yet.")
                break

    def add_signature(self, signature: bytes, protected: dict, unprotected: dict | None = None):
        """Add signature object to the envelope."""
        new_auth = self.create_authentication_block(protected, unprotected, signature)
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
        self._key_name = key_name
        self._key_id = key_id
        self._algorithm = algorithm
        self._context = context
        self._skip_signing = False
        self.envelope = input_envelope

        self.init_kms_backend(kms_script)
        self.already_signed_action(already_signed_action)

        if self._skip_signing:
            return self.envelope
        protected = {
            SuitIds.COSE_ALG.value: SuitCoseSignAlgorithms["COSE_ALG_" + self._algorithm.name].value,
            SuitIds.COSE_KEY_ID.value: cbor2.dumps(self._key_id),
        }
        cose = self.create_cose_structure(protected=protected)
        signature = self.kms.sign(cose, self._key_name, self._algorithm.value, self._context)
        self.add_signature(signature, protected=protected)
        return self.envelope


def suit_signer_factory():
    """Get a Signer object."""
    return Signer()
