#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for suit authentication parsing."""
import binascii
import pytest
from suit_generator.suit.manifest import (
    SuitManifest,
    SuitCommon,
    SuitComponents,
    SuitComponentIdentifier,
    SuitCommandSequence,
)

from suit_generator.suit.types.keys import suit_common, suit_manifest_version, suit_manifest_sequence_number

TEST_DATA = {
    "MANIFEST_DATA": (
        "a50101020003585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d"
        "51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f07"
        "4382030f0943821702"
    ),
    "COMMON_DATA": (
        "a202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab4503582482"
        "2f582000112233445566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f"
    ),
    "COMPONENTS_DATA": "81814100",
    "COMPONENT_IDENTIFIER_DATA": "814100",
    "COMMAND_SEQUENCE_DATA": (
        "8614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45035824822f5820001122334455"
        "66778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f"
    ),
}


@pytest.mark.parametrize(
    "suit_item, input_data",
    [
        (SuitComponents, "COMPONENTS_DATA"),
        (SuitComponentIdentifier, "COMPONENT_IDENTIFIER_DATA"),
        (SuitCommandSequence, "COMMAND_SEQUENCE_DATA"),
        (SuitCommon, "COMMON_DATA"),
    ],
)
def test_suit_item_parse(suit_item, input_data):
    """Check SuitComponents parsing from cbor."""
    suit_obj = suit_item.from_cbor(binascii.a2b_hex(TEST_DATA[input_data]))
    assert suit_obj is not None


def test_suit_manifest_parse():
    """Check SuitManifest parsing from cbor."""
    suit_obj = SuitManifest.from_cbor(binascii.a2b_hex(TEST_DATA["MANIFEST_DATA"]))
    assert suit_manifest_version in suit_obj.value
    assert suit_manifest_sequence_number in suit_obj.value
    assert suit_common in suit_obj.value


@pytest.mark.parametrize(
    "suit_item, input_data",
    [
        (SuitComponents, "COMPONENTS_DATA"),
        (SuitComponentIdentifier, "COMPONENT_IDENTIFIER_DATA"),
        (SuitCommandSequence, "COMMAND_SEQUENCE_DATA"),
        (SuitCommon, "COMMON_DATA"),
        (SuitManifest, "MANIFEST_DATA"),
    ],
)
def test_suit_item_parse_and_dump(suit_item, input_data):
    """Check SuitComponents parsing from cbor and dumping to cbor."""
    suit_obj = suit_item.from_cbor(binascii.a2b_hex(TEST_DATA[input_data]))
    assert suit_obj.to_cbor().hex() == TEST_DATA[input_data]
