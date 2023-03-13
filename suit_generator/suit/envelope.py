#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""SUIT envelope elements representation.

Code inspired by/based on https://github.com/tomchy/suit-composer.
"""

from suit_generator.suit.types.common import SuitKeyValue, SuitTag, Tag, Metadata, cbstr
from suit_generator.suit.authentication import SuitAuthenticationWrapper
from suit_generator.suit.manifest import SuitManifest, SuitCommandSequence, SuitTextMap
from suit_generator.suit.types.keys import (
    suit_manifest,
    suit_authentication_wrapper,
    suit_dependency_resolution,
    suit_payload_fetch,
    suit_install,
    suit_text,
)


class SuitEnvelope(SuitKeyValue):
    """Representation of SUIT_Envelope item."""

    # TODO: add missing items
    _metadata = Metadata(
        map={
            suit_manifest: cbstr(SuitManifest),
            suit_authentication_wrapper: cbstr(SuitAuthenticationWrapper),
            suit_dependency_resolution: cbstr(SuitCommandSequence),
            suit_payload_fetch: cbstr(SuitCommandSequence),
            suit_install: cbstr(SuitCommandSequence),
            suit_text: cbstr(SuitTextMap),
        }
    )


class SuitEnvelopeTagged(SuitTag):
    """Representation of SUIT_Envelope_Tagged item."""

    _metadata = Metadata(children=[SuitEnvelope], tag=Tag(107, "SUIT_Envelope_Tagged"))
