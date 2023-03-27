#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""SUIT envelope elements representation.

Code inspired by/based on https://github.com/tomchy/suit-composer.
"""
import binascii

from suit_generator.suit.payloads import SuitIntegratedPayloadMap
from suit_generator.suit.types.common import SuitKeyValue, SuitTag, Tag, Metadata, cbstr
from suit_generator.suit.authentication import SuitAuthentication, SuitHash
from suit_generator.suit.manifest import SuitManifest, SuitCommandSequence, SuitTextMap
from suit_generator.suit.types.keys import (
    suit_manifest,
    suit_authentication_wrapper,
    suit_dependency_resolution,
    suit_payload_fetch,
    suit_install,
    suit_text,
    suit_integrated_payloads,
)


class SuitEnvelope(SuitKeyValue):
    """Representation of SUIT_Envelope item."""

    # TODO: add missing items
    _metadata = Metadata(
        map={
            suit_manifest: cbstr(SuitManifest),
            suit_authentication_wrapper: cbstr(SuitAuthentication),
            suit_dependency_resolution: cbstr(SuitCommandSequence),
            suit_payload_fetch: cbstr(SuitCommandSequence),
            suit_install: cbstr(SuitCommandSequence),
            suit_text: cbstr(SuitTextMap),
            suit_integrated_payloads: SuitIntegratedPayloadMap,
        },
        embedded=[suit_integrated_payloads],
    )


class SuitEnvelopeTagged(SuitTag):
    """Representation of SUIT_Envelope_Tagged item."""

    _metadata = Metadata(children=[SuitEnvelope], tag=Tag(107, "SUIT_Envelope_Tagged"))

    def update_digest(self):
        """Update digest in the envelope."""
        # TODO: refactor and support for other cases required
        if hasattr(
            self.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper].SuitAuthentication,
            "SuitAuthenticationUnsigned",
        ):
            alg = (
                self.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
                .SuitAuthentication.SuitAuthenticationUnsigned[0]
                .SuitDigest.SuitDigestRaw[0]
                .value
            )
            manifest = self.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].to_cbor()
            hash_func = SuitHash(alg)
            new_digest = binascii.a2b_hex(hash_func.hash(manifest))
            self.SuitEnvelopeTagged.value.SuitEnvelope[
                suit_authentication_wrapper
            ].SuitAuthentication.SuitAuthenticationUnsigned[0].SuitDigest.SuitDigestRaw[1].SuitDigestBytes = new_digest
        else:
            raise Exception("Not possible to update digest!")
