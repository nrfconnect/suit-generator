#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""SUIT envelope elements representation.

Code inspired by/based on https://github.com/tomchy/suit-composer.
"""
from __future__ import annotations

import binascii
import pathlib

import cbor2

from suit_generator.suit.payloads import SuitIntegratedPayloadMap
from suit_generator.suit.types.common import SuitKeyValue, SuitTag, Tag, Metadata, SuitBstr, cbstr
from suit_generator.suit.authentication import SuitAuthentication, SuitHash, CoseSigStructure, SuitAuthenticationBlock
from suit_generator.suit.manifest import SuitManifest, SuitCommandSequence, SuitTextMap
from suit_generator.suit.types.keys import (
    suit_manifest,
    suit_authentication_wrapper,
    suit_dependency_resolution,
    suit_payload_fetch,
    suit_install,
    suit_text,
    suit_integrated_payloads,
    suit_integrated_dependencies,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from suit_generator.exceptions import SignerError


class KeyFactory:
    """Key factory implementation."""

    def __init__(self, private_key: EllipticCurvePrivateKey):
        """Initialize object."""
        self._key = private_key
        self._sign = self._get_sign_method()

    def sign(self, input_data: bytes) -> bytes:
        """Create signature for provided data."""
        return self._sign(input_data)

    def _get_sign_method(self) -> callable:
        """Return sign method based on key type."""
        if isinstance(self._key, EllipticCurvePrivateKey):
            return self._create_cose_es_signature
        else:
            raise SignerError(f"Key {type(self._key)} not supported")

    @property
    def algorithm_name(self):
        """Get algorithm name."""
        if isinstance(self._key, EllipticCurvePrivateKey):
            return f"cose-alg-es-{self._key.key_size}"
        else:
            raise SignerError(f"Key {type(self._key)} not supported")

    def _create_cose_es_signature(self, input_data: bytes) -> bytes:
        """Create ECDSA signature and return signature bytes."""
        hash_map = {256: hashes.SHA256(), 384: hashes.SHA384(), 521: hashes.SHA512()}
        dss_signature = self._key.sign(input_data, ec.ECDSA(hash_map[self._key.key_size]))
        r, s = decode_dss_signature(dss_signature)
        return r.to_bytes(self._key.key_size // 8, byteorder="big") + s.to_bytes(
            self._key.key_size // 8, byteorder="big"
        )


class SuitEnvelopeSimplified(SuitKeyValue):
    """Representation of SUIT_Envelope item."""

    _metadata = Metadata(
        map={
            suit_manifest: SuitBstr,
            suit_authentication_wrapper: cbstr(SuitAuthentication),
            suit_dependency_resolution: SuitBstr,
            suit_payload_fetch: SuitBstr,
            suit_install: SuitBstr,
            suit_text: SuitBstr,
            suit_integrated_payloads: SuitIntegratedPayloadMap,
        },
        embedded=[suit_integrated_payloads],
    )


class SuitEnvelope(SuitKeyValue):
    """Representation of SUIT_Envelope item."""

    _metadata = Metadata(
        map={
            suit_manifest: cbstr(SuitManifest),
            suit_authentication_wrapper: cbstr(SuitAuthentication),
            suit_dependency_resolution: cbstr(SuitCommandSequence),
            suit_payload_fetch: cbstr(SuitCommandSequence),
            suit_install: cbstr(SuitCommandSequence),
            suit_text: cbstr(SuitTextMap),
            suit_integrated_payloads: SuitIntegratedPayloadMap,
            suit_integrated_dependencies: SuitIntegratedPayloadMap,
        },
        embedded=[suit_integrated_payloads],
    )


class SuitBasicEnvelopeOperationsMixin:
    """Basic operations over envelopes."""

    def update_digest(self):
        """Update digest in the envelope."""
        alg = (
            self.value.value.value[suit_authentication_wrapper].SuitAuthentication[0].SuitDigest.SuitDigestRaw[0].value
        )
        manifest = self.value.value.value[suit_manifest].to_cbor()
        hash_func = SuitHash(alg)
        new_digest = binascii.a2b_hex(hash_func.hash(manifest))
        self.value.value.value[suit_authentication_wrapper].SuitAuthentication[0].SuitDigest.SuitDigestRaw[
            1
        ].SuitDigestBytes = new_digest

    def _create_authentication_block(self, algorithm_name: str) -> SuitAuthenticationBlock:
        """Create authentication wrapper."""
        return SuitAuthenticationBlock.from_obj(
            {
                "CoseSign1Tagged": {
                    "protected": {
                        "suit-cose-algorithm-id": algorithm_name,
                    },
                    "unprotected": {},
                    "payload": None,
                    "signature": "",
                }
            }
        )

    def _get_digest(self):
        """Return digest from parsed envelope."""
        return self.value.value.value[suit_authentication_wrapper].SuitAuthentication[0].SuitDigest

    def _create_cose_structure(self, digest_object: dict, algorithm_name: str) -> CoseSigStructure:
        """Create COSE_Sign1 structure."""
        return CoseSigStructure.from_obj(
            {
                "context": "Signature1",
                "body_protected": {"suit-cose-algorithm-id": algorithm_name},
                "external_add": "",
                "payload": digest_object,
            }
        )

    def update_severable_digests(self):
        """Update digest in the envelope for severed elements."""
        severable_elements = [suit_text, suit_payload_fetch, suit_install]
        for severable_element in severable_elements:
            if severable_element in self.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest and hasattr(
                self.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest[severable_element].value,
                "SuitDigest",
            ):
                alg = (
                    self.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest]
                    .SuitManifest[severable_element]
                    .value.SuitDigest.SuitDigestRaw[0]
                    .value
                )
                try:
                    # use cbor2.loads to unpack embedded cbor
                    object_data = cbor2.loads(self.SuitEnvelopeTagged.value.SuitEnvelope[severable_element].to_cbor())
                except KeyError:
                    # Data for digest calculation not available so skipp this element.
                    # This is expected case for creation of booting images when severable elements has been removed.
                    continue
                hash_func = SuitHash(alg)
                self.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest[
                    severable_element
                ].value.SuitDigest.SuitDigestRaw[1].value = binascii.a2b_hex(hash_func.hash(object_data))

    def sign(self, private_key: bytes):
        """Sign SUIT envelope."""
        key = KeyFactory(load_pem_private_key(private_key, None))
        digest = self._get_digest()
        suit_authentication_block = self._create_authentication_block(key.algorithm_name)
        cose_structure = self._create_cose_structure(digest.to_obj(), key.algorithm_name)

        signature = key.sign(cose_structure.to_cbor())

        suit_authentication_block.SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[3].SuitHex = signature

        self.value.value.value[suit_authentication_wrapper].SuitAuthentication.append(suit_authentication_block)

    @classmethod
    def return_processed_binary_data(cls, obj: dict | str):
        """Return binary SUIT envelope with updated digests."""
        if isinstance(obj, dict):
            suit_obj = cls.from_obj(obj)
            suit_obj.update_severable_digests()
            suit_obj.update_digest()
            # TODO: sign an envelope by calling external script for each and every generation
            return suit_obj.to_cbor()
        elif pathlib.Path(obj).is_file:
            with open(obj, "rb") as fh:
                return fh.read()


class SuitEnvelopeTaggedSimplified(SuitBasicEnvelopeOperationsMixin, SuitTag):
    """Representation of SUIT_Envelope_Tagged item."""

    _metadata = Metadata(children=[SuitEnvelopeSimplified], tag=Tag(107, "SUIT_Envelope_Tagged"))


class SuitEnvelopeTagged(SuitBasicEnvelopeOperationsMixin, SuitTag):
    """Representation of SUIT_Envelope_Tagged item."""

    _metadata = Metadata(children=[SuitEnvelope], tag=Tag(107, "SUIT_Envelope_Tagged"))
