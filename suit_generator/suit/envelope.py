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

from suit_generator.suit.payloads import SuitIntegratedPayloadMap
from suit_generator.suit.types.common import SuitKeyValue, SuitTag, Tag, Metadata, SuitBstr, cbstr
from suit_generator.suit.security import SuitDelegationChain, SuitAuthentication, SuitHash
from suit_generator.suit.manifest import SuitManifest, SuitCommandSequence, SuitTextMap
from suit_generator.suit.types.keys import (
    suit_manifest,
    suit_delegation,
    suit_authentication_wrapper,
    suit_dependency_resolution,
    suit_candidate_verification,
    suit_payload_fetch,
    suit_install,
    suit_install_legacy,
    suit_text,
    suit_integrated_payloads,
    suit_integrated_dependencies,
)


class SuitEnvelopeSimplified(SuitKeyValue):
    """Representation of SUIT_Envelope item."""

    _metadata = Metadata(
        map={
            suit_manifest: SuitBstr,
            suit_delegation: SuitDelegationChain,
            suit_authentication_wrapper: cbstr(SuitAuthentication),
            suit_dependency_resolution: SuitBstr,
            suit_payload_fetch: SuitBstr,
            suit_candidate_verification: SuitBstr,
            suit_install: SuitBstr,
            suit_install_legacy: SuitBstr,
            suit_text: SuitBstr,
            suit_integrated_payloads: SuitIntegratedPayloadMap,
            suit_integrated_dependencies: SuitIntegratedPayloadMap,
        },
        embedded=[suit_integrated_payloads],
    )


class SuitEnvelope(SuitKeyValue):
    """Representation of SUIT_Envelope item."""

    _metadata = Metadata(
        map={
            suit_manifest: cbstr(SuitManifest),
            suit_delegation: SuitDelegationChain,
            suit_authentication_wrapper: cbstr(SuitAuthentication),
            suit_dependency_resolution: cbstr(SuitCommandSequence),
            suit_payload_fetch: cbstr(SuitCommandSequence),
            suit_candidate_verification: cbstr(SuitCommandSequence),
            suit_install: cbstr(SuitCommandSequence),
            suit_install_legacy: cbstr(SuitCommandSequence),
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
        self.value.value.value[suit_authentication_wrapper].SuitAuthentication[0].SuitDigest.SuitDigestRaw[
            1
        ].SuitDigestBytes = self.get_manifest_digest(alg)

    def get_digest(self):
        """Return digest from parsed envelope."""
        return self.value.value.value[suit_authentication_wrapper].SuitAuthentication[0].SuitDigest

    def get_manifest(self):
        """Return manifest from parsed envelope."""
        return self.value.value.value[suit_manifest]

    def get_manifest_digest(self, alg):
        """Return digest from parsed envelope."""
        manifest = self.get_manifest().to_cbor()
        hash_func = SuitHash(alg)
        return binascii.a2b_hex(hash_func.hash(manifest))

    def update_severable_digests(self):
        """Update digest in the envelope for severed elements."""
        severable_elements = [
            suit_text,
            suit_dependency_resolution,
            suit_payload_fetch,
            suit_candidate_verification,
            suit_install,
            suit_install_legacy,
        ]
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
                    object_data = self.SuitEnvelopeTagged.value.SuitEnvelope[severable_element].to_cbor()
                except KeyError:
                    # Data for digest calculation not available so skip this element.
                    # This is expected case for creation of booting images when severable elements has been removed.
                    continue
                hash_func = SuitHash(alg)
                self.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest[
                    severable_element
                ].value.SuitDigest.SuitDigestRaw[1].value = binascii.a2b_hex(hash_func.hash(object_data))

    @classmethod
    def return_processed_binary_data(cls, obj: dict | str) -> bytes:
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
