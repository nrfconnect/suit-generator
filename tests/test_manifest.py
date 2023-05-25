#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for suit manifest parsing."""
import cbor2
from suit_generator.suit.manifest import SuitManifest
from suit_generator.suit.types.keys import suit_manifest_version, suit_manifest_sequence_number

MANIFEST_CONSTANTS = {"suit-manifest": 3, "suit-manifest-sequence-number": 2, "suit-manifest-version": 1}


def test_suit_manifest_from_cbor():
    """Check suit-manifest-version and suit-manifest-sequence-number parsing."""
    data = {MANIFEST_CONSTANTS["suit-manifest-version"]: 1, MANIFEST_CONSTANTS["suit-manifest-sequence-number"]: 12}
    suit_obj = SuitManifest.from_cbor(cbor2.dumps(data))
    assert suit_manifest_version in suit_obj.value
    assert suit_manifest_sequence_number in suit_obj.value
    assert suit_obj.value[suit_manifest_version].value == 1
    assert suit_obj.value[suit_manifest_sequence_number].value == 12
