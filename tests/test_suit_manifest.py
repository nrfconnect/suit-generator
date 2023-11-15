#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
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
    SuitComponentIdentifierPart,
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
    "COMPONENT_IDENTIFIER_DATA_MEMORY_ERROR": "ab5b2ca0b0a0000000a0a0a0",
    "COMMAND_SEQUENCE_DATA": (
        "8614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45035824822f5820001122334455"
        "66778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f"
    ),
}

TEST_DATA_FROM_OBJECT = {
    "COMMON_DATA": {
        "suit-components": [["M", 255, 235225088, 352256], ["M", 14, 772096000, 352256], ["D", 0]],
        "suit-shared-sequence": [
            {"suit-directive-set-component-index": 1},
            {
                "suit-directive-override-parameters": {
                    "suit-parameter-vendor-identifier": {"RFC4122_UUID": "nordicsemi.com"},
                    "suit-parameter-class-identifier": {"raw": "d622bafd4337518590bc6368cda7fbca"},
                }
            },
            {
                "suit-condition-vendor-identifier": [
                    "suit-send-record-success",
                    "suit-send-record-failure",
                    "suit-send-sysinfo-success",
                    "suit-send-sysinfo-failure",
                ]
            },
            {"suit-condition-class-identifier": []},
            {"suit-directive-set-component-index": True},
            {
                "suit-directive-override-parameters": {
                    "suit-parameter-image-digest": {
                        "suit-digest-algorithm-id": "cose-alg-sha-256",
                        "suit-digest-bytes": {"file": "file.bin"},
                    },
                    "suit-parameter-image-size": {"file": "file.bin"},
                }
            },
        ],
    }
}

TEST_DATA_COMPONENT_IDENTIFIER_DATA = [
    [0x0],
    ["D", 0x0],
    ["M", 14, 0x2E054000, 0x00056000],
    ["M", 0xFF, 0x0E054000, 0x00056000],
]


@pytest.mark.parametrize(
    "suit_item, input_data",
    [
        (SuitComponents, "COMPONENTS_DATA"),
        (SuitComponentIdentifier, "COMPONENT_IDENTIFIER_DATA"),
        (SuitComponentIdentifierPart, "COMPONENT_IDENTIFIER_DATA_MEMORY_ERROR"),
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


@pytest.mark.parametrize(
    "input_data",
    [
        [0x0],
        ["D", 0x0],
        ["M", 14, 0x2E054000, 0x00056000],
        ["M", 0xFF, 0x0E054000, 0x00056000],
        ["A", 0xFF, 0x00, 0xFF],
        [0xBEEF, 0xFF, 0x00, 0xFF],
    ],
)
def test_suit_component_identifier_from_object(input_data):
    """Check SuitComponents parsing from cbor."""
    suit_obj = SuitComponentIdentifier.from_obj(input_data)
    assert hasattr(suit_obj, "SuitComponentIdentifier")
    assert len(suit_obj.SuitComponentIdentifier) == len(input_data)
    for index, _ in enumerate(input_data):
        assert hasattr(suit_obj.SuitComponentIdentifier[index], "SuitComponentIdentifierPart")


@pytest.mark.parametrize(
    "input_data",
    ["COMMON_DATA"],
)
def test_suit_common_from_obj(input_data):
    suit_obj = SuitCommon.from_obj(TEST_DATA_FROM_OBJECT[input_data])
    assert hasattr(suit_obj, "SuitCommon")
    assert type(suit_obj.SuitCommon) is dict
