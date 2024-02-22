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

import math

import cbor2
import uuid

from argparse import ArgumentParser
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from collections import defaultdict
from enum import Enum, unique

PRIVATE_KEY = Path(__file__).parent / "key_private.pem"


@unique
class SuitAlgorithms(Enum):
    """Suit algorithms."""

    COSE_ALG_SHA_256 = -16
    COSE_ALG_SHAKE128 = -18
    COSE_ALG_SHA_384 = -43
    COSE_ALG_SHA_512 = -44
    COSE_ALG_SHAKE256 = -45
    COSE_ALG_ES_256 = -7
    COSE_ALG_ES_384 = -35
    COSE_ALG_ES_521 = -36
    COSE_ALG_EdDSA = -8


class SuitIds(Enum):
    """Suit elements identifiers."""

    COSE_ALG = 1
    COSE_KEY_ID = 4
    SUIT_MANIFEST = 3
    SUIT_AUTHENTICATION_WRAPPER = 2
    SUIT_MANIFEST_COMPONENT_ID = 5


DEFAULT_KEY_ID = 0x7FFFFFE0

KEY_IDS = {"nRF54H20_sample_root": 0x7FFFFFE0, "nRF54H20_sample_app": 0x7FFFFFE0, "nRF54H20_sample_rad": 0x7FFFFFE0}

DOMAIN_NAME = "nordicsemi.com"


class SignerError(Exception):
    """Signer exception."""


class Signer:
    """Signer implementation."""

    def __init__(self):
        """Initialize signer."""
        domain_name = uuid.uuid5(uuid.NAMESPACE_DNS, DOMAIN_NAME)
        self._key_ids = defaultdict(lambda: DEFAULT_KEY_ID)
        for name, val in KEY_IDS.items():
            self._key_ids[uuid.uuid5(domain_name, name).hex] = val

    @staticmethod
    def create_authentication_block(protected: dict | None, unprotected: dict | None, signature: bytes):
        """Create Authentication Block."""
        data = [cbor2.dumps(protected), unprotected if unprotected is not None else {}, None, signature]
        auth_block = cbor2.CBORTag(18, data)
        return auth_block

    def create_cose_structure(self, protected: dict):
        """Create COSE Sig_structure."""
        data = ["Signature1", cbor2.dumps(protected), b"", cbor2.dumps(self.get_digest())]
        return cbor2.dumps(data)

    def get_digest(self):
        """Return digest object."""
        auth_block = cbor2.loads(self.envelope.value[SuitIds.SUIT_AUTHENTICATION_WRAPPER.value])
        digest = cbor2.loads(auth_block[0])
        return digest

    def add_signature(self, signature: bytes, protected: dict, unprotected: dict | None = None):
        """Add signature object to the envelope."""
        new_auth = self.create_authentication_block(protected, unprotected, signature)
        auth_block = cbor2.loads(self.envelope.value[SuitIds.SUIT_AUTHENTICATION_WRAPPER.value])
        auth_block.append(cbor2.dumps(new_auth))
        self.envelope.value[SuitIds.SUIT_AUTHENTICATION_WRAPPER.value] = cbor2.dumps(auth_block)

    def load_envelope(self, input_file: Path) -> None:
        """Load suit envelope."""
        with open(input_file, "rb") as fh:
            self.envelope = cbor2.load(fh)

    def save_envelope(self, output_file: Path) -> None:
        """Store envelope."""
        with open(output_file, "wb") as fh:
            cbor2.dump(self.envelope, fh)

    def _get_sign_method(self) -> callable:
        """Return sign method based on key type."""
        if isinstance(self._key, EllipticCurvePrivateKey):
            return self._create_cose_es_signature
        elif isinstance(self._key, Ed25519PrivateKey):
            return self._create_cose_ed_signature
        else:
            raise SignerError(f"Key {type(self._key)} not supported")

    @property
    def _algorithm_name(self) -> str:
        """Get algorithm name."""
        hash_alg = SuitAlgorithms(self.get_digest()[0])
        if isinstance(self._key, EllipticCurvePrivateKey):
            return f"COSE_ALG_ES_{self._key.key_size}"
        elif isinstance(self._key, Ed25519PrivateKey):
            return "COSE_ALG_EdDSA"
        else:
            raise SignerError(f"Key {type(self._key)} with {hash_alg} is not supported")

    def _create_cose_es_signature(self, input_data: bytes) -> bytes:
        """Create ECDSA signature and return signature bytes."""
        hash_map = {256: hashes.SHA256(), 384: hashes.SHA384(), 521: hashes.SHA512()}
        dss_signature = self._key.sign(input_data, ec.ECDSA(hash_map[self._key.key_size]))
        r, s = decode_dss_signature(dss_signature)
        return r.to_bytes(math.ceil(self._key.key_size / 8), byteorder="big") + s.to_bytes(
            math.ceil(self._key.key_size / 8), byteorder="big"
        )

    def _create_cose_ed_signature(self, input_data: bytes) -> bytes:
        """Create ECDSA signature and return signature bytes."""
        return self._key.sign(input_data)

    def _get_manifest_class_id(self):
        manifest = cbor2.loads(self.envelope.value[SuitIds.SUIT_MANIFEST.value])
        if (
            SuitIds.SUIT_MANIFEST_COMPONENT_ID.value in manifest
            and len(manifest[SuitIds.SUIT_MANIFEST_COMPONENT_ID.value]) == 2
        ):
            return manifest[SuitIds.SUIT_MANIFEST_COMPONENT_ID.value][1].hex()
        else:
            return None

    def _get_key_id_for_manifest_class(self):
        return self._key_ids[self._get_manifest_class_id()]

    def sign(self, private_key_path: Path) -> None:
        """Add signature to the envelope."""
        with open(private_key_path, "rb") as private_key:
            self._key = load_pem_private_key(private_key.read(), None)
        sign_method = self._get_sign_method()
        protected = {
            SuitIds.COSE_ALG.value: SuitAlgorithms[self._algorithm_name].value,
            SuitIds.COSE_KEY_ID.value: cbor2.dumps(self._get_key_id_for_manifest_class()),
        }
        cose = self.create_cose_structure(protected=protected)
        signature = sign_method(cose)
        self.add_signature(signature, protected=protected)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--input-file", required=True, type=Path, help="Input envelope.")
    parser.add_argument("--output-file", required=True, type=Path, help="Output envelope.")

    arguments = parser.parse_args()

    signer = Signer()
    signer.load_envelope(arguments.input_file)
    signer.sign(PRIVATE_KEY)
    signer.save_envelope(arguments.output_file)
