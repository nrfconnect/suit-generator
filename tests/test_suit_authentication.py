#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for suit authentication parsing."""
import binascii
import pytest
from suit_generator.suit.authentication import SuitAuthentication, CoseSigStructure
from suit_generator.suit.types.keys import suit_cose_algorithm_id

TEST_DATA = {
    "AUTHENTICATION_WRAPPER_DATA_DIGEST_ONLY": (
        "815824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af"
    ),
    "AUTHENTICATION_WRAPPER_DATA_AUTHENTICATION_BLOCK": (
        "825824822F58202CCA9D1D8D12460B2C3242DD3B1269C3BEF8FAC53DCC9EDAAFC4FB12B5260AB1"
        "584AD28443A10126A0F65840A1BE08C59DBBC4471FB0C79BDF2BF1306507B6C84E0DD18F79AEB8"
        "A30B320404C6F57399967F8C66FF816659309BF7AD8957A5E1997EF8335490848F0AE77568"
    ),
    "AUTHENTICATION_WRAPPER_DATA_AUTHENTICATION_BLOCK_TWICE": (
        "835824822F5820F429BA01A650F9430D8759CDA5F69DC75D7A389683E986576C75513BACE432D9"
        "584AD28443A10126A0F65840149A9C4B1BDAB46F7F46A6200A7F8A46FB2BF6F4F87933E07F9D29"
        "3C2894ED2F225C83744CBB60337E8858E8F1BBBCEEE2642F500A7C28B1B84EC1CD136D081D584A"
        "D28443A10126A0F65840D686E1BB235FD660B6421F1076802F93ED17034BFD7F55671F46C44C1C"
        "D32FBF0007871452EDFEAAEA0FED59885CC3DAC77B081EBA354EF0C323B0C7D03EF0DF"
    ),
}

TEST_DATA_OBJECT = {
    "SIGNED_AUTHENTICATION_WRAPPER_ONE_SIGNATURE": {
        "SuitDigest": {"suit-digest-algorithm-id": "cose-alg-sha-256", "suit-digest-bytes": "deadbeef"},
        "SuitAuthenticationBlock": {
            "CoseSign1Tagged": {
                "protected": {
                    "suit-cose-algorithm-id": "cose-alg-es-256",
                },
                "unprotected": {},
                "payload": None,
                "signature": "deadbeef00",
            }
        },
    },
    "SIGNED_AUTHENTICATION_WRAPPER_TWO_SIGNATURES": {
        "SuitDigest": {"suit-digest-algorithm-id": "cose-alg-sha-256", "suit-digest-bytes": "deadbeef"},
        "SuitAuthenticationInternalExample": {
            "CoseSign1Tagged": {
                "protected": {
                    "suit-cose-algorithm-id": "cose-alg-es-256",
                },
                "unprotected": {},
                "payload": None,
                "signature": "deadbeef01",
            }
        },
        "SuitAuthenticationExternal": {
            "CoseSign1Tagged": {
                "protected": {"suit-cose-algorithm-id": "cose-alg-es-256"},
                "unprotected": {},
                "payload": None,
                "signature": "deadbeef02",
            }
        },
    },
    "UNSIGNED_AUTHENTICATION_WRAPPER": {
        "SuitDigest": {"suit-digest-algorithm-id": "cose-alg-sha-256", "suit-digest-bytes": "aaabbbcccdddeeefff"},
    },
}


@pytest.mark.parametrize(
    "input_data",
    [
        "UNSIGNED_AUTHENTICATION_WRAPPER",
        "SIGNED_AUTHENTICATION_WRAPPER_ONE_SIGNATURE",
        "SIGNED_AUTHENTICATION_WRAPPER_TWO_SIGNATURES",
    ],
)
def test_suit_authentication_wrapper_content_from_obj(input_data):
    suit_obj = SuitAuthentication.from_obj(TEST_DATA_OBJECT[input_data])
    assert suit_obj.value is not None


@pytest.mark.parametrize(
    "input_data",
    [
        "UNSIGNED_AUTHENTICATION_WRAPPER",
        "SIGNED_AUTHENTICATION_WRAPPER_ONE_SIGNATURE",
        "SIGNED_AUTHENTICATION_WRAPPER_TWO_SIGNATURES",
    ],
)
def test_suit_authentication_wrapper_from_obj(input_data):
    suit_obj = SuitAuthentication.from_obj(TEST_DATA_OBJECT[input_data])
    suit_binary = suit_obj.to_cbor()
    assert suit_obj.value is not None
    assert suit_binary.hex() == SuitAuthentication.from_cbor(suit_binary).to_cbor().hex()


@pytest.mark.parametrize(
    "input_data",
    [
        "AUTHENTICATION_WRAPPER_DATA_DIGEST_ONLY",
        "AUTHENTICATION_WRAPPER_DATA_AUTHENTICATION_BLOCK",
        "AUTHENTICATION_WRAPPER_DATA_AUTHENTICATION_BLOCK_TWICE",
    ],
)
def test_suit_authentication_wrapper_from_cbor(input_data):
    """Check authentication-wrapper parsing for only digest in it."""

    suit_obj = SuitAuthentication.from_cbor(binascii.a2b_hex(TEST_DATA[input_data]))
    assert suit_obj.value is not None


@pytest.mark.parametrize(
    "input_data", ["AUTHENTICATION_WRAPPER_DATA_DIGEST_ONLY", "AUTHENTICATION_WRAPPER_DATA_AUTHENTICATION_BLOCK"]
)
def test_suit_authentication_wrapper_from_cbor_parse_and_dump(input_data):
    """Check authentication-wrapper parsing for only digest in it."""

    suit_obj = SuitAuthentication.from_cbor(binascii.a2b_hex(TEST_DATA[input_data]))
    assert suit_obj.to_cbor().hex().upper() == TEST_DATA[input_data].upper()


def test_sig_structure():
    """Test if is possible to create Sig_structure."""
    test_obj = {
        "context": "Signature1",
        "body_protected": {"suit-cose-algorithm-id": "cose-alg-es-256"},
        "external_add": "",
        "payload": {"suit-digest-algorithm-id": "cose-alg-sha-256", "suit-digest-bytes": "aaabbbcccdddeeefff"},
    }
    structure = CoseSigStructure.from_obj(test_obj)
    hex_value = structure.to_cbor().hex()
    assert structure is not None
    assert type(structure) is CoseSigStructure
    assert hasattr(structure, "CoseSigStructure")
    assert len(structure.CoseSigStructure) == 4
    assert structure.CoseSigStructure[0].value == "Signature1"
    assert structure.CoseSigStructure[1].SuitHeaderMap[suit_cose_algorithm_id].SuitcoseSignAlg == "cose-alg-es-256"
    assert structure.CoseSigStructure[2].SuitHex == b""
    assert structure.CoseSigStructure[3].to_cbor().hex().upper() == "4C822F49AAABBBCCCDDDEEEFFF"
    assert hex_value is not None


def test_two_auth_block_to_dict_obj():
    """Check if is possible to restore dict from suit object containing two authentication blocks."""
    suit_obj = SuitAuthentication.from_cbor(
        binascii.a2b_hex(TEST_DATA["AUTHENTICATION_WRAPPER_DATA_AUTHENTICATION_BLOCK_TWICE"])
    )
    dict_obj = suit_obj.to_obj()
    assert len(dict_obj) == 3
    for key in ["SuitAuthentication1", "SuitAuthentication2", "SuitDigest"]:
        assert key in dict_obj
