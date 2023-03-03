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

MANIFEST_DATA = (
    "a50101020003585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d"
    "51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f07"
    "4382030f0943821702"
)


COMMON_DATA = (
    "a202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab4503582482"
    "2f582000112233445566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f"
)

COMPONENTS_DATA = "81814100"

COMPONENT_IDENTIFIER_DATA = "814100"

COMMAND_SEQUENCE_DATA = (
    "8614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45035824822f5820001122334455"
    "66778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f"
)


def test_suit_components_parsing():
    """Check SuitComponents parsing from cbor."""
    suit_obj = SuitComponents.from_cbor(binascii.a2b_hex(COMPONENTS_DATA))
    assert suit_obj is not None


def test_suit_component_identifier_parsing():
    """Check SuitComponentIdentifier parsing from cbor."""
    suit_obj = SuitComponentIdentifier.from_cbor(binascii.a2b_hex(COMPONENT_IDENTIFIER_DATA))
    assert suit_obj is not None


def test_suit_command_sequence():
    """Check SuitCommandSequence parsing from cbor."""
    suit_obj = SuitCommandSequence.from_cbor(binascii.a2b_hex(COMMAND_SEQUENCE_DATA))
    assert suit_obj is not None


def test_suit_common_parsing():
    """Check SuitCommon parsing from cbor."""
    suit_obj = SuitCommon.from_cbor(binascii.a2b_hex(COMMON_DATA))
    assert suit_obj is not None


def test_suit_manifest_parsing():
    """Check SuitManifest parsing from cbor."""
    suit_obj = SuitManifest.from_cbor(binascii.a2b_hex(MANIFEST_DATA))
    assert suit_manifest_version in suit_obj.value
    assert suit_manifest_sequence_number in suit_obj.value
    assert suit_common in suit_obj.value


def test_suit_components_parsing_dumping():
    """Check SuitComponents parsing from cbor and dumping to cbor."""
    suit_obj = SuitComponents.from_cbor(binascii.a2b_hex(COMPONENTS_DATA))
    assert suit_obj.to_cbor().hex() == COMPONENTS_DATA


def test_suit_component_identifier_parsing_dumping():
    """Check SuitComponentIdentifier parsing from cbor and dumping to cbor."""
    suit_obj = SuitComponentIdentifier.from_cbor(binascii.a2b_hex(COMPONENT_IDENTIFIER_DATA))
    assert suit_obj.to_cbor().hex() == COMPONENT_IDENTIFIER_DATA


def test_suit_command_sequence_dumping():
    """Check SuitCommandSequence parsing from cbor and dumping to cbor."""
    suit_obj = SuitCommandSequence.from_cbor(binascii.a2b_hex(COMMAND_SEQUENCE_DATA))
    assert suit_obj.to_cbor().hex() == COMMAND_SEQUENCE_DATA


def test_suit_common_parsing_dumping():
    """Check SuitCommon parsing from cbor and dumping to cbor."""
    suit_obj = SuitCommon.from_cbor(binascii.a2b_hex(COMMON_DATA))
    assert suit_obj.to_cbor().hex() == COMMON_DATA


def test_suit_manifest_parsing_dumping():
    """Check SuitManifest parsing from cbor and dumping to cbor."""
    suit_obj = SuitManifest.from_cbor(binascii.a2b_hex(MANIFEST_DATA))
    assert suit_obj.to_cbor().hex() == MANIFEST_DATA
