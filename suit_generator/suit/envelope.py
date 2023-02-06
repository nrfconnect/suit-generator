#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""SUIT envelope elements representation.

Code inspired by/based on https://github.com/tomchy/suit-composer.
"""

from suit_generator.suit.types.common import SuitKeyValue, SuitTag, Tag, Metadata
from suit_generator.suit.authentication import SuitAuthenticationWrapper
from suit_generator.suit.manifest import SuitManifest
from suit_generator.suit.types.keys import suit_manifest, suit_authentication_wrapper


class SuitEnvelope(SuitKeyValue):
    """Representation of SUIT_Envelope item."""

    metadata = Metadata(map={suit_manifest: SuitManifest, suit_authentication_wrapper: SuitAuthenticationWrapper})


class SuitEnvelopeTagged(SuitTag):
    """Representation of SUIT_Envelope_Tagged item."""

    metadata = Metadata(children=[SuitEnvelope], tag=Tag(107, "SUIT_Envelope_Tagged"))
