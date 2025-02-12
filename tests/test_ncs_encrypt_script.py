#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for ncs example signing script."""
import pytest
import pathlib
import os
import cbor2
import json

# from cryptography.hazmat.primitives import hashes

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA384, SHA512

from suit_generator.suit_encrypt_script_base import SuitKWAlgorithms, SuitDigestAlgorithms


from suit_generator.suit.security import CoseEncryptTagged, CoseEncStructure

from ncs.encrypt_script import suit_encryptor_factory
import ncs.basic_kms

import kms_script_mock

# DATA for encrypt and generate keys

TEMP_DIRECTORY = pathlib.Path("test_test_data")

# fmt: off
CONTENT_ENCRYPTION_KEY = bytes([0xea, 0x2d, 0xa4, 0x58, 0x80, 0x2a, 0xcf, 0x9f, 0xdd, 0x9a, 0xef, 0xde,
                                0x3b, 0xb6, 0x0a, 0xec, 0xca, 0x4b, 0xe0, 0x46, 0xb7, 0x31, 0x45, 0x99,
                                0xd2, 0x2e, 0xbb, 0xc4, 0x79, 0x3c, 0x14, 0x0a])

KEY_ENCRYPTION_KEY = bytes([0xcd, 0xca, 0x25, 0xf7, 0x16, 0xb7, 0x7c, 0xe1, 0x88, 0xf3, 0xda, 0xef,
                            0x11, 0x5e, 0x1f, 0x14, 0x5a, 0x38, 0x0e, 0x74, 0xb2, 0x14, 0xb6, 0x73,
                            0x33, 0xa7, 0x2d, 0x88, 0xd4, 0xfa, 0x45, 0xe3])

SAMPLE_DATA = bytes([0x34, 0x9c, 0xd7, 0xce, 0x75, 0xe5, 0x4f, 0x55, 0xa1, 0x16, 0xc8, 0xdc,
                     0xdc, 0x6a, 0x6b, 0x49, 0x3c, 0xf1, 0x09, 0x38, 0xe7, 0xa9, 0x31, 0xc5,
                     0xbe, 0xfd, 0x6f, 0xe7, 0x57, 0x83, 0x37, 0xd4, 0x92, 0xf9, 0x20, 0xbc,
                     0x1f, 0xb5, 0x99, 0x9c, 0xa8, 0x37, 0x29, 0x45, 0x5b, 0x1d, 0x5a, 0x4c,
                     0x59, 0x61, 0x10, 0xa5, 0xea, 0x91, 0x10, 0xdc, 0xe4, 0x3a, 0xca, 0xd0,
                     0x18, 0xd6, 0x6b, 0x46, 0x5d, 0x81, 0x14, 0x39, 0xfd, 0x91, 0x6d, 0x7e,
                     0xe7, 0x16, 0x13, 0xa8, 0x0a, 0x75, 0xc0, 0xcf, 0x74, 0xd3, 0x02, 0x91,
                     0x5e, 0x70, 0xad, 0xe0, 0x13, 0x7b, 0x2c, 0x21, 0xff, 0x15, 0xbe, 0x6a,
                     0x55, 0xb1, 0xd6, 0x8a, 0x64, 0x4e, 0xd0, 0x7b, 0x03, 0x5f, 0xb0, 0xdb,
                     0x23, 0xb7, 0x04, 0x2c, 0xa9, 0x9e, 0x1e, 0x51, 0x60, 0x36, 0x20, 0x68,
                     0x59, 0x54, 0xbd, 0x80, 0x14, 0x9d, 0x0c, 0x00, 0xa5, 0x97, 0xa3, 0x39,
                     0x95, 0xce, 0x41, 0xe5, 0xfd, 0x84, 0xb0, 0x65, 0x98, 0xce, 0x4d, 0xda,
                     0x59, 0xe2, 0x36, 0x10, 0x72, 0xa9, 0x8b, 0xcc, 0x04, 0xd5, 0xd0, 0x71,
                     0x44, 0x58, 0x90, 0xe6, 0xb0, 0xe9, 0xf0, 0x9f, 0xc8, 0x4d, 0x5c, 0x15,
                     0x08, 0xdb, 0x0d, 0x34, 0xca, 0x05, 0x2b, 0xbc, 0x28, 0x9c, 0x50, 0xbb,
                     0xa8, 0xbd, 0x29, 0x6a, 0xfd, 0x26, 0xc5, 0x79, 0x00, 0x52, 0x7e, 0x90,
                     0x26, 0xbf, 0x96, 0x8c, 0x3b, 0x4f, 0x69, 0x90, 0xcc, 0xe3, 0x86, 0xca,
                     0x9f, 0x1a, 0x14, 0xa0, 0x7c, 0x7f, 0x7b, 0xac, 0xc3, 0xed, 0xee, 0x08,
                     0x63, 0x9f, 0x4c, 0xbe, 0x65, 0x95, 0x56, 0x29, 0xb7, 0x5e, 0x1d, 0xe4,
                     0x01, 0x8c, 0x5d, 0x05, 0xff, 0x2f, 0x1b, 0xb8, 0xd0, 0x74, 0xf1, 0xcd,
                     0xde, 0xd9, 0xcf, 0xeb, 0xc7, 0x73, 0x56, 0x5c, 0xf6, 0x2c, 0xb6, 0xc1,
                     0xf4, 0x6a, 0xfe, 0xb1, 0x66, 0x2d, 0x2d, 0x90, 0xc2, 0xdb, 0xba, 0xb6,
                     0x69, 0x9e, 0xf1, 0x20, 0xc5, 0x12, 0xd9, 0x27, 0x82, 0x87, 0x10, 0xcb,
                     0x29, 0xf4, 0x86, 0x9d, 0x9e, 0x14, 0xf2, 0xae, 0x2a, 0x88, 0xb3, 0x30,
                     0x9c, 0xde, 0xc4, 0x30, 0x72, 0x20, 0x1c, 0x2d, 0x3f, 0xa8, 0xff, 0x8c,
                     0xec, 0xa8, 0xd7, 0xd7, 0xaa, 0xb9, 0x0c, 0x1a, 0x34, 0x6c, 0xc8, 0x1b,])

SAMPLE_NONCE = bytes([0xe7, 0xee, 0xb8, 0x79, 0x11, 0x51, 0xa0, 0x66, 0x41, 0x58, 0x62, 0x57])

# Used only to test generate, not a real tag resulting from encryption using the data above
SAMPLE_TAG = bytes([0x7c, 0x29, 0x7c, 0x05, 0xed, 0x52, 0xcb, 0x7d, 0x54, 0xf0, 0x62, 0x0b, 0x93, 0xfd, 0x1f, 0xdb])
# fmt: on

SAMPLE_KEY_ID = 0x40000123

ENC_STRUCTURE_CONST = CoseEncStructure.from_obj(
    {"context": "Encrypt", "protected": {"suit-cose-algorithm-id": "cose-alg-aes-gcm-256"}, "external_aad": ""}
).to_cbor()


@pytest.fixture
def setup_and_teardown(tmp_path_factory):
    """Create and cleanup environment."""
    # Setup environment
    #   - create required files in TEMP_DIRECTORY
    start_directory = os.getcwd()
    path = tmp_path_factory.mktemp(TEMP_DIRECTORY)
    os.chdir(path)
    with open("kek_aes.bin", "wb") as fh:
        fh.write(KEY_ENCRYPTION_KEY)
    with open("cek_aes.bin", "wb") as fh:
        fh.write(CONTENT_ENCRYPTION_KEY)
    yield
    # Cleanup environment
    #   - remove temp directory
    os.chdir(start_directory)


def test_generate_aes_direct():
    """Test the generate function with AES GCM direct."""
    encrypted_asset = SAMPLE_NONCE + SAMPLE_TAG + SAMPLE_DATA

    encryptor = suit_encryptor_factory()
    encrypted_payload, tag, encryption_info = encryptor.generate(
        encrypted_asset, None, SAMPLE_KEY_ID, SuitKWAlgorithms.DIRECT
    )

    assert encrypted_payload == SAMPLE_DATA
    assert tag == SAMPLE_TAG

    enc_info_unserialized = cbor2.loads(encryption_info)
    enc_info_parsed = CoseEncryptTagged.from_cbor(enc_info_unserialized).value.value.to_obj()

    assert enc_info_parsed["protected"]["suit-cose-algorithm-id"] == "cose-alg-aes-gcm-256"
    assert enc_info_parsed["unprotected"]["suit-cose-iv"] == SAMPLE_NONCE.hex()
    assert enc_info_parsed["ciphertext"] is None

    enc_info_recipient = enc_info_parsed["recipients"][0]

    assert enc_info_recipient["protected"] == ""
    assert enc_info_recipient["unprotected"]["suit-cose-algorithm-id"] == "cose-alg-direct"
    assert enc_info_recipient["unprotected"]["suit-cose-key-id"] == SAMPLE_KEY_ID
    assert enc_info_recipient["ciphertext"] is None


def test_generate_aes_kw():
    """Test the generate function with AES GCM with AES256KW."""
    encrypted_asset = SAMPLE_NONCE + SAMPLE_TAG + SAMPLE_DATA

    encryptor = suit_encryptor_factory()
    encrypted_payload, tag, encryption_info = encryptor.generate(
        encrypted_asset, CONTENT_ENCRYPTION_KEY, SAMPLE_KEY_ID, SuitKWAlgorithms.A256KW
    )

    assert encrypted_payload == SAMPLE_DATA
    assert tag == SAMPLE_TAG

    enc_info_unserialized = cbor2.loads(encryption_info)
    enc_info_parsed = CoseEncryptTagged.from_cbor(enc_info_unserialized).value.value.to_obj()

    assert enc_info_parsed["protected"]["suit-cose-algorithm-id"] == "cose-alg-aes-gcm-256"
    assert enc_info_parsed["unprotected"]["suit-cose-iv"] == SAMPLE_NONCE.hex()
    assert enc_info_parsed["ciphertext"] is None

    enc_info_recipient = enc_info_parsed["recipients"][0]

    assert enc_info_recipient["protected"] == ""
    assert enc_info_recipient["unprotected"]["suit-cose-algorithm-id"] == "cose-alg-a256kw"
    assert enc_info_recipient["unprotected"]["suit-cose-key-id"] == SAMPLE_KEY_ID
    assert enc_info_recipient["ciphertext"] == CONTENT_ENCRYPTION_KEY.hex()


def _sha_alg_to_object(alg: SuitDigestAlgorithms):
    if alg == SuitDigestAlgorithms.SHA_256:
        return SHA256.new()
    elif alg == SuitDigestAlgorithms.SHA_384:
        return SHA384.new()
    elif alg == SuitDigestAlgorithms.SHA_512:
        return SHA512.new()
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")


@pytest.mark.parametrize(
    "sha_alg",
    [SuitDigestAlgorithms.SHA_256, SuitDigestAlgorithms.SHA_384, SuitDigestAlgorithms.SHA_512],
)
def test_encrypt_and_generate_aes_direct(setup_and_teardown, sha_alg):
    """Test the generate function with AES GCM direct."""

    encryptor = suit_encryptor_factory()

    encrypted_payload, tag, encryption_info, digest, plaintext_length = encryptor.encrypt_and_generate(
        SAMPLE_DATA,
        "cek_aes",
        SAMPLE_KEY_ID,
        os.path.dirname(os.path.realpath("cek_aes.bin")),
        sha_alg,
        SuitKWAlgorithms.DIRECT,
        ncs.basic_kms.__file__,
    )

    assert plaintext_length == len(SAMPLE_DATA)

    hash = _sha_alg_to_object(sha_alg).new()
    hash.update(SAMPLE_DATA)
    assert digest == hash.digest()

    enc_info_unserialized = cbor2.loads(encryption_info)
    enc_info_parsed = CoseEncryptTagged.from_cbor(enc_info_unserialized).value.value.to_obj()

    assert enc_info_parsed["protected"]["suit-cose-algorithm-id"] == "cose-alg-aes-gcm-256"
    assert enc_info_parsed["ciphertext"] is None

    enc_info_recipient = enc_info_parsed["recipients"][0]

    assert enc_info_recipient["protected"] == ""
    assert enc_info_recipient["unprotected"]["suit-cose-algorithm-id"] == "cose-alg-direct"
    assert enc_info_recipient["unprotected"]["suit-cose-key-id"] == SAMPLE_KEY_ID
    assert enc_info_recipient["ciphertext"] is None

    iv = bytes.fromhex(enc_info_parsed["unprotected"]["suit-cose-iv"])

    cipher = AES.new(CONTENT_ENCRYPTION_KEY, AES.MODE_GCM, nonce=iv)
    cipher.update(ENC_STRUCTURE_CONST)
    decrypted_payload = cipher.decrypt_and_verify(encrypted_payload, tag)

    assert decrypted_payload == SAMPLE_DATA


@pytest.mark.parametrize(
    "ctx, key_id, key_name, plaintext, iv, test_tag, encrypted_data",
    [
        ("test_ctx", SAMPLE_KEY_ID, "test_key_name", SAMPLE_DATA, SAMPLE_NONCE, SAMPLE_TAG, b"Encrypted data"),
        ("ctx2", 0x12345678, "key_name2", b"plaintext2", b"sample_iv12b", b"sample_tag16byte", b"Encrypted data2"),
    ],
)
def test_encrypt_script_kms_script_usage(
    setup_and_teardown, ctx, key_id, key_name, plaintext, iv, test_tag, encrypted_data
):
    """Test if the encrypt_script uses the KMS script correctly."""

    # Sanity check for the test parameters
    assert len(test_tag) == 16
    assert len(iv) == 12

    full_context = json.dumps(
        {
            "ctx": ctx,
            "iv": iv.hex(),
            "tag": test_tag.hex(),
            "encrypted_data": encrypted_data.hex(),
            "output_file": "test_encrypt_output_file.json",
        }
    )

    encryptor = suit_encryptor_factory()

    encrypted_payload, tag, encryption_info, digest, plaintext_length = encryptor.encrypt_and_generate(
        plaintext,
        key_name,
        key_id,
        full_context,
        SuitDigestAlgorithms.SHA_256,
        SuitKWAlgorithms.DIRECT,
        kms_script_mock.__file__,
    )

    assert plaintext_length == len(plaintext)
    assert digest == SHA256.new(plaintext).digest()
    assert encrypted_payload == encrypted_data
    assert tag == test_tag

    saved_data = json.load(open("test_encrypt_output_file.json"))
    assert saved_data["init_kms_ctx"] == ctx
    assert saved_data["encrypt_plaintext"] == plaintext.hex()
    assert saved_data["encrypt_key_name"] == key_name
    assert saved_data["encrypt_context"] == ctx
    assert saved_data["encrypt_aad"] == ENC_STRUCTURE_CONST.hex()

    enc_info_unserialized = cbor2.loads(encryption_info)
    enc_info_parsed = CoseEncryptTagged.from_cbor(enc_info_unserialized).value.value.to_obj()

    assert enc_info_parsed["protected"]["suit-cose-algorithm-id"] == "cose-alg-aes-gcm-256"
    assert enc_info_parsed["ciphertext"] is None
    assert enc_info_parsed["unprotected"]["suit-cose-iv"] == iv.hex()

    enc_info_recipient = enc_info_parsed["recipients"][0]

    assert enc_info_recipient["protected"] == ""
    assert enc_info_recipient["unprotected"]["suit-cose-algorithm-id"] == "cose-alg-direct"
    assert enc_info_recipient["unprotected"]["suit-cose-key-id"] == key_id
    assert enc_info_recipient["ciphertext"] is None
