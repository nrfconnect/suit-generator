#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Envelope extension provides basic API to envelope data."""
from __future__ import annotations

from suit_generator.suit.types.keys import (
    suit_manifest,
    suit_manifest_version,
    suit_manifest_sequence_number,
    suit_manifest_component_id,
    suit_current_version,
    suit_authentication_wrapper,
    suit_digest_algorithm_id,
    suit_digest_bytes,
)


class EnvelopeApiMixin:
    """Implementation of envelope API."""

    @property
    def sequence_number(self) -> int:
        """Return suit-manifest-sequence-number value."""
        return self._envelope["SUIT_Envelope_Tagged"][suit_manifest.name][suit_manifest_sequence_number.name]

    @property
    def manifest_version(self) -> int:
        """Return suit-manifest-version value."""
        return self._envelope["SUIT_Envelope_Tagged"][suit_manifest.name][suit_manifest_version.name]

    @property
    def digest_bytes(self) -> str:
        """Return suit-digest-bytes value encoded as hex."""
        return self._envelope["SUIT_Envelope_Tagged"][suit_authentication_wrapper.name]["SuitDigest"][
            suit_digest_bytes.name
        ]

    @property
    def digest_algorithm(self) -> str:
        """Return suit-digest-algorithm-id value."""
        return self._envelope["SUIT_Envelope_Tagged"][suit_authentication_wrapper.name]["SuitDigest"][
            suit_digest_algorithm_id.name
        ]

    @property
    def manifest_component_id(self) -> list | None:
        """Return suit-manifest-component-id value."""
        if suit_manifest_component_id.name in self._envelope["SUIT_Envelope_Tagged"][suit_manifest.name]:
            return self._envelope["SUIT_Envelope_Tagged"][suit_manifest.name][suit_manifest_component_id.name]
        else:
            return None

    @property
    def current_version(self) -> list | None:
        """Return suit-current-version value."""
        if suit_current_version.name in self._envelope["SUIT_Envelope_Tagged"][suit_manifest.name]:
            return self._envelope["SUIT_Envelope_Tagged"][suit_manifest.name][suit_current_version.name]
        else:
            return None
