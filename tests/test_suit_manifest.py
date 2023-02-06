#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for suit authentication parsing."""
import binascii
from suit_generator.suit.manifest import (
    SuitManifest,
    SuitCommon,
    SuitComponents,
    SuitComponentIdentifier,
    SuitCommandSequence,
)

from suit_generator.suit.types.keys import suit_common, suit_manifest_version, suit_manifest_sequence_number


def test_suit_manifest_parsing():
    """Check suit manifest parsing."""
    data = (
        "a50101020003585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d"
        "51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f07"
        "4382030f0943821702"
    )
    suit_obj = SuitManifest.from_cbor(binascii.a2b_hex(data))
    assert suit_manifest_version in suit_obj.value
    assert suit_manifest_sequence_number in suit_obj.value
    assert suit_common in suit_obj.value


def test_suit_common_parsing():
    data = (
        "a202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab4503582482"
        "2f582000112233445566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f"
    )
    suit_obj = SuitCommon.from_cbor(binascii.a2b_hex(data))
    assert suit_obj is not None


def test_suit_components_parsing():
    data = "81814100"
    suit_obj = SuitComponents.from_cbor(binascii.a2b_hex(data))
    assert suit_obj is not None


def test_suit_component_identifier_parsing():
    data = "814100"
    suit_obj = SuitComponentIdentifier.from_cbor(binascii.a2b_hex(data))
    assert suit_obj is not None


def test_suit_command_sequence():
    data = (
        "8614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45035824822f5820001122334455"
        "66778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f"
    )
    suit_obj = SuitCommandSequence.from_cbor(binascii.a2b_hex(data))
    assert suit_obj is not None
