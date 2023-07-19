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
)

from suit_generator.suit.types.keys import (
    suit_common,
    suit_manifest_version,
    suit_manifest_sequence_number,
    suit_manifest_component_id,
)


TEST_DATA = {
    "MANIFEST_DATA": (
        "a4010102010358e2a20283824143410082414950816aa0a0af115ef2858afeb668b2e9c98241495008c1b59955e85fbc9e767bc2"
        "9ce1b04d0458af8e0c0114a401507617daa571fd5a858f94e28d735ce9f40250816aa0a0af115ef2858afeb668b2e9c903582482"
        "2f582056af1101b2e9519e663a721fdd1f83cc87708abe889287512cd9cd17c470fa1b0e1902380c0214a401507617daa571fd5a"
        "858f94e28d735ce9f4025008c1b59955e85fbc9e767bc29ce1b04d035824822f5820cf50b37ec5b28e804088ee1b1c8a5b33cdc9"
        "4e5b0bd10ec893ec1e4207aa86b20e1902380c8201020100020005824149503f6a3a4dcdfa58c5accef9f584c41124"
    ),
    "COMMON_DATA": (
        "a20283824143410082414950816aa0a0af115ef2858afeb668b2e9c98241495008c1b59955e85fbc9e767bc29ce1b04d0458af8e"
        "0c0114a401507617daa571fd5a858f94e28d735ce9f40250816aa0a0af115ef2858afeb668b2e9c9035824822f582056af1101b2"
        "e9519e663a721fdd1f83cc87708abe889287512cd9cd17c470fa1b0e1902380c0214a401507617daa571fd5a858f94e28d735ce9"
        "f4025008c1b59955e85fbc9e767bc29ce1b04d035824822f5820cf50b37ec5b28e804088ee1b1c8a5b33cdc94e5b0bd10ec893ec"
        "1e4207aa86b20e1902380c82010201000200"
    ),
    "COMPONENTS_DATA": "83824143410082414950816aa0a0af115ef2858afeb668b2e9c98241495008c1b59955e85fbc9e767bc29ce1b04d",
    "COMPONENT_IDENTIFIER_DATA_C": "8241434100",
    "COMPONENT_IDENTIFIER_DATA_RAD": "82414950816aa0a0af115ef2858afeb668b2e9c9",
    "COMPONENT_IDENTIFIER_DATA_APP": "8241495008c1b59955e85fbc9e767bc29ce1b04d",
    "COMMAND_SEQUENCE_DATA": (
        "8e0c0114a401507617daa571fd5a858f94e28d735ce9f40250816aa0a0af115ef2858afeb668b2e9c9035824822f582056af1101"
        "b2e9519e663a721fdd1f83cc87708abe889287512cd9cd17c470fa1b0e1902380c0214a401507617daa571fd5a858f94e28d735c"
        "e9f4025008c1b59955e85fbc9e767bc29ce1b04d035824822f5820cf50b37ec5b28e804088ee1b1c8a5b33cdc94e5b0bd10ec893"
        "ec1e4207aa86b20e1902380c82010201000200"
    ),
    "MANIFEST_CLASS_ID_DATA": ("824149503f6a3a4dcdfa58c5accef9f584c41124"),
}

TEST_DATA_FROM_OBJECT = {
    "COMMON_DATA": {
        "suit-components": [
            ["C", 0],
            ["I", {"RFC4122_UUID": {"namespace": "nordicsemi.com", "name": "nRF54H20_sample_rad"}}],
            ["I", {"RFC4122_UUID": {"namespace": "nordicsemi.com", "name": "nRF54H20_sample_app"}}],
        ],
        "suit-shared-sequence": [
            {"suit-directive-set-component-index": 1},
            {
                "suit-directive-override-parameters": {
                    "suit-parameter-vendor-identifier": {
                        "RFC4122_UUID": {"name": "nordicsemi.com"},
                    },
                    "suit-parameter-class-identifier": {
                        "RFC4122_UUID": {"namespace": "nordicsemi.com", "name": "nRF54H20_sample_rad"}
                    },
                    "suit-parameter-image-digest": {
                        "suit-digest-algorithm-id": "cose-alg-sha-256",
                        "suit-digest-bytes": "56af1101b2e9519e663a721fdd1f83cc87708abe889287512cd9cd17c470fa1b",
                    },
                    "suit-parameter-image-size": {"raw": 568},
                }
            },
            {"suit-directive-set-component-index": 2},
            {
                "suit-directive-override-parameters": {
                    "suit-parameter-vendor-identifier": {
                        "RFC4122_UUID": {"name": "nordicsemi.com"},
                    },
                    "suit-parameter-class-identifier": {
                        "RFC4122_UUID": {"namespace": "nordicsemi.com", "name": "nRF54H20_sample_app"}
                    },
                    "suit-parameter-image-digest": {
                        "suit-digest-algorithm-id": "cose-alg-sha-256",
                        "suit-digest-bytes": "cf50b37ec5b28e804088ee1b1c8a5b33cdc94e5b0bd10ec893ec1e4207aa86b2",
                    },
                    "suit-parameter-image-size": {"raw": 568},
                }
            },
            {"suit-directive-set-component-index": [1, 2]},
            {"suit-condition-vendor-identifier": []},
            {"suit-condition-class-identifier": []},
        ],
    },
    "suit-manifest-component-id": [
        "I",
        {"RFC4122_UUID": {"namespace": "nordicsemi.com", "name": "nRF54H20_sample_root"}},
    ],
}


@pytest.mark.parametrize(
    "suit_item, input_data",
    [
        (SuitComponents, "COMPONENTS_DATA"),
        (SuitComponentIdentifier, "COMPONENT_IDENTIFIER_DATA_C"),
        (SuitComponentIdentifier, "COMPONENT_IDENTIFIER_DATA_RAD"),
        (SuitComponentIdentifier, "COMPONENT_IDENTIFIER_DATA_APP"),
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
    assert suit_manifest_component_id in suit_obj.value
    print(suit_obj.to_obj())


@pytest.mark.parametrize(
    "suit_item, input_data",
    [
        (SuitComponents, "COMPONENTS_DATA"),
        (SuitComponentIdentifier, "COMPONENT_IDENTIFIER_DATA_C"),
        (SuitComponentIdentifier, "COMPONENT_IDENTIFIER_DATA_RAD"),
        (SuitComponentIdentifier, "COMPONENT_IDENTIFIER_DATA_APP"),
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
        ["C", 0],
        ["I", {"raw": "816aa0a0af115ef2858afeb668b2e9c9"}],
        ["I", {"RFC4122_UUID": {"namespace": "nordicsemi.com", "name": "nRF54H20_sample_root"}}],
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
