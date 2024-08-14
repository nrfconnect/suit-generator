#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for suit encryption parsing."""
import binascii
import pytest

from suit_generator.suit.security import CoseEncryptTagged

TEST_DATA = {
    "COSE_ENCRYPT_FROM_SPEC": (
        "D8608443A10101A10550F14AAB9D81D51F7AD943FE87AF4F70CDF6818340"
        "A2012204456B69642D31581875603FFC9518D794713C8CA8A115A7FB3256"
        "5A6D59534D62"
    ),
}

TEST_DATA_OBJECT = {
    "COSE_ENCRYPT_FROM_SPEC": {
        "CoseEncryptTagged": {
            "protected": {
                "suit-cose-algorithm-id": "cose-alg-aes-gcm-128",
            },
            "unprotected": {"suit-cose-iv": "f14aab9d81d51f7ad943fe87af4f70cd"},
            "ciphertext": None,
            "recipients": [
                {
                    "protected": {},
                    "unprotected": {
                        "suit-cose-algorithm-id": "cose-alg-a128kw",
                        "suit-cose-key-id": "6b69642d31",  # "kid-1"
                    },
                    "ciphertext": "75603ffc9518d794713c8ca8a115a7fb32565a6d59534d62",
                },
            ],
        }
    },
}


@pytest.mark.parametrize(
    "input_data",
    [
        "COSE_ENCRYPT_FROM_SPEC",
    ],
)
def test_suit_cose_encrypt_content_from_obj(input_data):
    suit_obj = CoseEncryptTagged.from_obj(TEST_DATA_OBJECT[input_data])
    assert suit_obj.value is not None


@pytest.mark.parametrize(
    "input_data",
    [
        "COSE_ENCRYPT_FROM_SPEC",
    ],
)
def test_suit_cose_encrypt_from_obj(input_data):
    suit_obj = CoseEncryptTagged.from_obj(TEST_DATA_OBJECT[input_data])
    suit_binary = suit_obj.to_cbor()
    assert suit_obj.value is not None
    assert suit_binary.hex() == CoseEncryptTagged.from_cbor(suit_binary).to_cbor().hex()


@pytest.mark.parametrize(
    "input_data",
    [
        "COSE_ENCRYPT_FROM_SPEC",
    ],
)
def test_suit_cose_encrypt_from_cbor(input_data):
    suit_obj = CoseEncryptTagged.from_cbor(binascii.a2b_hex(TEST_DATA[input_data]))
    assert suit_obj.value is not None


@pytest.mark.parametrize(
    "input_data",
    [
        "COSE_ENCRYPT_FROM_SPEC",
    ],
)
def test_suit_cose_encrypt_from_cbor_parse_and_dump(input_data):
    suit_obj = CoseEncryptTagged.from_cbor(binascii.a2b_hex(TEST_DATA[input_data]))
    assert suit_obj.to_cbor().hex().upper() == TEST_DATA[input_data].upper()


@pytest.mark.parametrize(
    "input_data",
    [
        "COSE_ENCRYPT_FROM_SPEC",
    ],
)
def test_suit_cose_encrypt_to_cbor_result(input_data):
    suit_obj = CoseEncryptTagged.from_obj(TEST_DATA_OBJECT[input_data])
    assert suit_obj.to_cbor().hex().upper() == TEST_DATA[input_data].upper()
