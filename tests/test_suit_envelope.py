#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for SUIT internal envelope representation."""
import pytest
import binascii

from suit_generator.suit.authentication import CoseSigStructure
from suit_generator.suit.envelope import SuitEnvelopeTagged
from suit_generator.suit.types.keys import (
    suit_authentication_wrapper,
    suit_manifest,
    suit_manifest_sequence_number,
    suit_manifest_version,
    suit_common,
    suit_integrated_payloads,
    suit_cose_algorithm_id,
)
from deepdiff import DeepDiff
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

PRIVATE_KEYS = {
    "ES_256": b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCCbgTEad8JOIU8sg
IJUKm7Lle0358XoaxNfbs4nqd4WhRANCAATt0J6l7OTtvmwI50cJVZo4KcUxMyJ7
9PARbowFLQIODsPg2Df0wm/BKIAvRTgaIytt1dooYABdq+Kgg9vvOFUT
-----END PRIVATE KEY-----""",
    "ES_384": b"""-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCw/iNctq9pFyKI/fem
p/CmNMyMyMnM29D4aajftXjkJQJv/ei/jTWFV5RbyBQiU8mhZANiAATp3RsCAE7E
C+9ywexwCwCqFS5thWjpXJfcrN+KaqRJ65H5r1cHmZB7sLj/qIPgclrNWA+qau7H
SybGG+k1OCi30FZSSo7Ozv8jarYr8NvoQnyI6+01Mo5TaOqC9a+41p8=
-----END PRIVATE KEY-----
""",
}

TEST_DATA = {
    "ENVELOPE_1_UNSIGNED": (
        "d86ba2025827815824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5a"
        "f035871a50101020003585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe025014"
        "92af1425695e48bf429b2d51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abc"
        "deffedcba98765432100e1987d0010f020f074382030f0943821702"
    ),
    "ENVELOPE_2_UNSIGNED": (
        "d86ba4025827815824822f5820d8e4fb7c2a95b0ef8d56d55641d1ea214f503b33af4aa348768c453e1d029d9"
        "f0358bba70101020203585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe025014"
        "92af1425695e48bf429b2d51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abc"
        "deffedcba98765432100e1987d0010f020f074382030f094382170211822f5820cfa90c5c58595e7f5119a72f"
        "803fd0370b3e6abbec6315cd38f63135281bc49817822f58209b9d629701fc35ffca609f9244267fb25c8703b"
        "9b3ff9820c66576e0cf976f9611586f8614a1157865687474703a2f2f6578616d706c652e636f6d2f76657279"
        "2f6c6f6e672f706174682f746f2f66696c652f66696c652f3132332f3435362f3738392f6162632f6465662f6"
        "768692f6a6b6c2f6d6e6f2f7072732f7475762f7778792f7a2f66696c652e62696e1502030f1759019ca20179"
        "01727465737420656e76656c6f706520666f7220737569742d67656e657261746f722c2077697468207665727"
        "9206c6f6e6720737472696e67206162636465666768696a6b6c6d6f6e6f70727374757778797a313233343536"
        "3738396162636465666768696a6b6c6d6f6e6f70727374757778797a313233343536373839616263646566676"
        "8696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f7072"
        "7374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a3132333"
        "435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465"
        "666768696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6"
        "f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a31"
        "32333435363738395c6e5c6e5c6e5c6e814100a4036d6e6f7264696373656d692e6e6f0464737569740564746"
        "57374066476313233"
    ),
    "ENVELOPE_3_UNSIGNED": (
        "d86ba3025827815824822f58201fa5ac823699866eea2636e35d8839b500edca78017293ec170ee46b93de1c5d"
        "03587fa701010201035839a2028181441e05400004582d8614a301502bdc1c07e0d15484be5063174d5a74c302"
        "508520ea9c515e57798b5fbdad67dec7d90e00010f020f074382030f0943821702114d8214a11568236170702e"
        "62696e17822f58203abeaa152b7b1af05d37eab6d31062288ed3d72f24cb5c51eb0e9dd90a124118175887a181"
        "441e054000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246353432305f6370"
        "75617070036d6e6f7264696373656d692e6e6f04781d546865206e52463533383430206170706c69636174696f"
        "6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e302e30"
    ),
    "ENVELOPE_4_UNSIGNED_NEGATIVE_SEQUENCE_NUMBER": (
        "d86ba3025827815824822f5820e66ba02fc45f1c8eef3af2f923dde400647340889a281fa5f28b3e123486a5c10"
        "35883a70101023a075bcd14035839a2028181441e05400004582d8614a301502bdc1c07e0d15484be5063174d5a"
        "74c302508520ea9c515e57798b5fbdad67dec7d90e00010f020f074382030f0943821702114d8214a1156823617"
        "0702e62696e17822f58203abeaa152b7b1af05d37eab6d31062288ed3d72f24cb5c51eb0e9dd90a124118175887"
        "a181441e054000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246353432305f6"
        "37075617070036d6e6f7264696373656d692e6e6f04781d546865206e52463533383430206170706c6963617469"
        "6f6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e302e30"
    ),
    "ENVELOPE_5_SIGNED": (
        "d86ba2025873825824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af584ad2"
        "8443a10126a0f65840e3505f7ab70bd3a0e04916f37b0d7251aa6f52ca12c7edaa886a4129a298ca6a1ecc2a57955c6b"
        "f4ccb9f01d684d5d1c4774dffbe508a034431feafa60848a2c035871a50101020003585fa202818141000458568614a4"
        "0150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45035824822f58200011223344"
        "5566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f074382030f0943821702"
    ),
    "ENVELOPE_6_UNSIGNED_COMPONENT_LIST": (
        "d86ba3025827815824822f5820baf46a70509a15160ae825e70991bb24fc27668a2292a42f243a420c55bfa3fe03588a"
        "a701010201035844a2028184414d4102451a0e054000451a0005600004582d8614a301502bdc1c07e0d15484be506317"
        "4d5a74c302508520ea9c515e57798b5fbdad67dec7d90e00010f020f074382030f0943821702114d8214a11568236170"
        "702e62696e17822f5820bd5cc7c73cd96cdb9bf6dbd59693f5adb6c76873b76eea169fa40ced69ffe43b175892a18441"
        "4d4102451a0e054000451a00056000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246"
        "353432305f637075617070036d6e6f7264696373656d692e6e6f04781d546865206e52463533383430206170706c6963"
        "6174696f6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e302e30"
    ),
}

TEST_INPUT_OBJECT_UNSIGNED = {
    "SUIT_Envelope_Tagged": {
        "suit-authentication-wrapper": {
            "SuitDigest": {"suit-digest-algorithm-id": "cose-alg-sha-256", "suit-digest-bytes": "aaabbbcccdddeeefff"},
        },
        "suit-manifest": {
            "suit-manifest-version": 1,
            "suit-manifest-sequence-number": 1,
            "suit-common": {
                "suit-components": [["M", 255, 235225088, 352256], ["M", 14, 772096000, 352256], ["D", 0]],
                "suit-shared-sequence": [
                    {"suit-directive-set-component-index": 1},
                    {
                        "suit-directive-override-parameters": {
                            "suit-parameter-vendor-identifier": {"RFC4122_UUID": "nordicsemi.no"},
                            "suit-parameter-class-identifier": {"raw": "8520ea9c515e57798b5fbdad67dec7d9"},
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
            },
            "suit-install": [
                {"suit-directive-set-component-index": 2},
                {"suit-directive-override-parameters": {"suit-parameter-uri": "#file.bin"}},
                {"suit-directive-fetch": []},
                {"suit-condition-image-match": []},
                {"suit-directive-set-component-index": 1},
                {"suit-directive-override-parameters": {"suit-parameter-source-component": 2}},
                {"suit-directive-copy": []},
                {"suit-condition-image-match": []},
            ],
            "suit-validate": [{"suit-directive-set-component-index": 1}, {"suit-condition-image-match": []}],
            "suit-load": [
                {"suit-directive-set-component-index": 0},
                {"suit-directive-override-parameters": {"suit-parameter-source-component": 1}},
                {"suit-directive-copy": []},
                {"suit-condition-image-match": []},
            ],
            "suit-invoke": [{"suit-directive-set-component-index": 0}, {"suit-directive-invoke": []}],
        },
        "suit-text": {
            '["M", 2, 235577344, 352256]': {
                "suit-text-vendor-name": "Nordic Semiconductor ASA",
                "suit-text-model-name": "nRF5420_cpuapp",
                "suit-text-vendor-domain": "nordicsemi.no",
                "suit-text-model-info": "The nRF5420 application core",
                "suit-text-component-description": "Sample application core FW",
                "suit-text-component-version": "v1.0.0",
            }
        },
        "suit-integrated-payloads": {"#file.bin": "file.bin"},
    }
}

TEST_INPUT_OBJECT_SIGNED = {
    "SuitEnvelopeTagged": {
        "suit-authentication-wrapper": {
            "SuitAuthentication": {
                "SuitDigest": {"suit-digest-algorithm-id": "cose-alg-sha-256"},
                "SuitAuthenticationBlock": {
                    "CoseSign1Tagged": {
                        "protected": {"suit-cose-algorithm-id": "cose-alg-es-256"},
                        "unprotected": {},
                        "payload": None,
                        "signature": "",
                    }
                },
            },
        },
        "suit-manifest": {
            "suit-manifest-version": 1,
            "suit-manifest-sequence-number": {"raw": 1},
            "suit-common": {
                "suit-components": [["M", 255, 235225088, 352256], ["M", 14, 772096000, 352256], ["D", 0]],
                "suit-shared-sequence": [
                    {"suit-directive-set-component-index": 1},
                    {
                        "suit-directive-override-parameters": {
                            "suit-parameter-vendor-identifier": {"RFC4122_UUID": "nordicsemi.no"},
                            "suit-parameter-class-identifier": {"raw": "8520ea9c515e57798b5fbdad67dec7d9"},
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
            },
            "suit-install": [
                {"suit-directive-set-component-index": 2},
                {"suit-directive-override-parameters": {"suit-parameter-uri": "#file.bin"}},
                {"suit-directive-fetch": []},
                {"suit-condition-image-match": []},
                {"suit-directive-set-component-index": 1},
                {"suit-directive-override-parameters": {"suit-parameter-source-component": 2}},
                {"suit-directive-copy": []},
                {"suit-condition-image-match": []},
            ],
            "suit-validate": [{"suit-directive-set-component-index": 1}, {"suit-condition-image-match": []}],
            "suit-load": [
                {"suit-directive-set-component-index": 0},
                {"suit-directive-override-parameters": {"suit-parameter-source-component": 1}},
                {"suit-directive-copy": []},
                {"suit-condition-image-match": []},
            ],
            "suit-invoke": [{"suit-directive-set-component-index": 0}, {"suit-directive-invoke": []}],
        },
        "suit-integrated-payloads": {"#file.bin": "file.bin", "file2.bin": "file.bin"},
    }
}

BINARY_FILE = (
    "c79cab9de8337f3014ebac02af26015e806d88a1db11a731dfa6eccb9b480dc834406d30867de81bec3cf540d"
    "0481882119d7c3f6ce58ff1d35de151f76a0faf0bbd4c5fa5341a66db22ec63ed4babc7c8f759d8d69eec711b"
    "2420b9aee13bfcaeb877aca4573497844f58d568086fe39c7e1bd738229848f87a67b2d9acc534c127828e427"
    "98421374c414a0fe27fa06a19133d52227fd62f711276ab259cfc6708037cdb18e645f899c29e2ce39b25a97b"
    "09ff005726080a1142cf82a26b2a99f9719d14195c5c783160424a181fec786a9a7c4fcfe85a2965cd013b6d5"
    "3bbc6dbdad58ff7f4d9b90a034bff33ab3bc5afd0b82c0f6aa911b0e8578c925381"
)


@pytest.mark.parametrize(
    "input_envelope",
    ["ENVELOPE_1_UNSIGNED", "ENVELOPE_2_UNSIGNED", "ENVELOPE_3_UNSIGNED", "ENVELOPE_6_UNSIGNED_COMPONENT_LIST"],
)
def test_parse_unsigned_envelope(input_envelope):
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA[input_envelope]))
    assert type(envelope.SuitEnvelopeTagged.value.SuitEnvelope) is dict
    assert suit_authentication_wrapper in envelope.SuitEnvelopeTagged.value.SuitEnvelope.keys()
    assert suit_manifest in envelope.SuitEnvelopeTagged.value.SuitEnvelope.keys()
    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication.SuitAuthenticationUnsigned[0]
        .SuitDigest.SuitDigestRaw[0]
        .SuitCoseHashAlg
        == "cose-alg-sha-256"
    )
    for required_item in [suit_manifest_sequence_number, suit_manifest_version, suit_common]:
        assert required_item in envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest.keys()


@pytest.mark.parametrize("input_envelope", ["ENVELOPE_1_UNSIGNED", "ENVELOPE_2_UNSIGNED", "ENVELOPE_3_UNSIGNED"])
def test_parse_unsigned_envelope_parse_and_dump(input_envelope):
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA[input_envelope]))
    assert envelope.to_cbor().hex() == TEST_DATA[input_envelope]


def test_parse_signed_envelope():
    """Test if is possible to parse complete signed envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA["ENVELOPE_5_SIGNED"]))
    assert envelope._metadata.tag.name == "SUIT_Envelope_Tagged"
    assert envelope._metadata.tag.value == 107
    assert type(envelope.SuitEnvelopeTagged.value.SuitEnvelope) is dict
    assert suit_authentication_wrapper in envelope.value.value.value.keys()
    assert suit_manifest in envelope.value.value.value.keys()
    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication.SuitAuthenticationSigned[0]
        .SuitDigest.SuitDigestRaw[0]
        .SuitCoseHashAlg
        == "cose-alg-sha-256"
    )
    for required_item in [suit_manifest_sequence_number, suit_manifest_version, suit_common]:
        assert required_item in envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest.keys()


def test_conversion_obj_to_cbor():
    """Test if is possible to convert object to cbor."""
    envelope = SuitEnvelopeTagged.from_obj(TEST_INPUT_OBJECT_UNSIGNED)
    assert type(envelope.SuitEnvelopeTagged.value.SuitEnvelope) is dict
    assert suit_authentication_wrapper in envelope.SuitEnvelopeTagged.value.SuitEnvelope.keys()
    assert suit_manifest in envelope.SuitEnvelopeTagged.value.SuitEnvelope.keys()
    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication.SuitAuthenticationUnsigned[0]
        .SuitDigest.SuitDigestRaw[0]
        .SuitCoseHashAlg
        == "cose-alg-sha-256"
    )
    for required_item in [suit_manifest_sequence_number, suit_manifest_version, suit_common]:
        assert required_item in envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest.keys()
    assert suit_integrated_payloads in envelope.SuitEnvelopeTagged.value.SuitEnvelope
    binary_envelope = envelope.to_cbor()
    hex = binary_envelope.hex()
    assert hex is not None
    envelope2 = SuitEnvelopeTagged.from_cbor(binary_envelope)
    assert binary_envelope.hex() == envelope2.to_cbor().hex()


def test_conversion_obj_to_obj():
    """Test if is possible to convert object to object."""
    envelope = SuitEnvelopeTagged.from_obj(TEST_INPUT_OBJECT_UNSIGNED)
    suit_obj = envelope.to_obj()
    assert (
        "raw"
        in suit_obj["SUIT_Envelope_Tagged"]["suit-manifest"]["suit-common"]["suit-shared-sequence"][1][
            "suit-directive-override-parameters"
        ]["suit-parameter-vendor-identifier"]
    )
    assert (
        "raw"
        in suit_obj["SUIT_Envelope_Tagged"]["suit-manifest"]["suit-common"]["suit-shared-sequence"][5][
            "suit-directive-override-parameters"
        ]["suit-parameter-image-size"]
    )
    # exclude suit-integrated-payloads, suit-parameter-vendor-identifier and suit-parameter-image-size
    # due to expected different output structure
    diff = DeepDiff(
        TEST_INPUT_OBJECT_UNSIGNED,
        suit_obj,
        exclude_paths=[
            "root['SUIT_Envelope_Tagged']['suit-integrated-payloads']",
            "root['SUIT_Envelope_Tagged']['suit-manifest']['suit-common']['suit-shared-sequence'][1]"
            "['suit-directive-override-parameters']['suit-parameter-vendor-identifier']",
            "root['SUIT_Envelope_Tagged']['suit-manifest']['suit-common']['suit-shared-sequence'][5]"
            "['suit-directive-override-parameters']['suit-parameter-image-size']",
        ],
    )
    assert diff == {}


def test_conversion_obj_to_cbor_to_obj():
    """Test if is possible to convert object to cbor to object."""
    envelope = SuitEnvelopeTagged.from_obj(TEST_INPUT_OBJECT_UNSIGNED)
    binary_envelope = envelope.to_cbor()
    envelope2 = SuitEnvelopeTagged.from_cbor(binary_envelope)
    suit_obj = envelope2.to_obj()
    assert (
        "raw"
        in suit_obj["SUIT_Envelope_Tagged"]["suit-manifest"]["suit-common"]["suit-shared-sequence"][1][
            "suit-directive-override-parameters"
        ]["suit-parameter-vendor-identifier"]
    )
    assert (
        "raw"
        in suit_obj["SUIT_Envelope_Tagged"]["suit-manifest"]["suit-common"]["suit-shared-sequence"][5][
            "suit-directive-override-parameters"
        ]["suit-parameter-image-size"]
    )
    # exclude suit-integrated-payloads, suit-parameter-vendor-identifier and suit-parameter-image-size
    # due to expected different output structure
    diff = DeepDiff(
        TEST_INPUT_OBJECT_UNSIGNED,
        suit_obj,
        exclude_paths=[
            "root['SUIT_Envelope_Tagged']['suit-integrated-payloads']",
            "root['SUIT_Envelope_Tagged']['suit-manifest']['suit-common']['suit-shared-sequence'][1]"
            "['suit-directive-override-parameters']['suit-parameter-vendor-identifier']",
            "root['SUIT_Envelope_Tagged']['suit-manifest']['suit-common']['suit-shared-sequence'][5]"
            "['suit-directive-override-parameters']['suit-parameter-image-size']",
        ],
    )
    assert diff == {}


def test_conversion_obj_to_cbor_to_obj_to_cbor():
    """Test if is possible to convert object to cbor to object to cbor."""
    binary_envelope = SuitEnvelopeTagged.from_obj(TEST_INPUT_OBJECT_UNSIGNED).to_cbor()
    suit_obj = SuitEnvelopeTagged.from_cbor(binary_envelope).to_obj()
    binary_envelope_2 = SuitEnvelopeTagged.from_obj(suit_obj).to_cbor()
    assert binary_envelope_2.hex() == binary_envelope.hex()


def test_digest_update():
    """Test if is possible to update digest."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA["ENVELOPE_1_UNSIGNED"]))
    digest_bytes_before_update = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication.SuitAuthenticationUnsigned[0]
        .SuitDigest.SuitDigestRaw[1]
        .value
    )
    envelope.update_digest()
    digest_bytes_after_update = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication.SuitAuthenticationUnsigned[0]
        .SuitDigest.SuitDigestRaw[1]
        .value
    )
    assert digest_bytes_after_update == digest_bytes_before_update


def test_digest_update_after_value_change():
    """Test if is possible to update digest."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA["ENVELOPE_1_UNSIGNED"]))
    digest_bytes_before_update = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication.SuitAuthenticationUnsigned[0]
        .SuitDigest.SuitDigestRaw[1]
        .value
    )
    envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest[
        suit_manifest_sequence_number
    ].SuitUint = 123
    envelope.update_digest()
    digest_bytes_after_update = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication.SuitAuthenticationUnsigned[0]
        .SuitDigest.SuitDigestRaw[1]
        .value
    )
    assert digest_bytes_after_update.hex() != digest_bytes_before_update.hex()


@pytest.mark.parametrize(
    "private_key",
    ["ES_256", "ES_384"],
)
def test_envelope_signing(private_key):
    """Test if is possible to sign manifest."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA["ENVELOPE_1_UNSIGNED"]))
    envelope.update_digest()
    envelope.sign(PRIVATE_KEYS[private_key])
    assert envelope is not None
    assert suit_authentication_wrapper in envelope.SuitEnvelopeTagged.value.SuitEnvelope
    assert hasattr(envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper], "SuitAuthentication")
    assert hasattr(
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper].SuitAuthentication,
        "SuitAuthenticationSigned",
    )
    assert (
        len(
            envelope.SuitEnvelopeTagged.value.SuitEnvelope[
                suit_authentication_wrapper
            ].SuitAuthentication.SuitAuthenticationSigned
        )
        == 2
    )
    assert hasattr(
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[
            suit_authentication_wrapper
        ].SuitAuthentication.SuitAuthenticationSigned[0],
        "SuitDigest",
    )


def test_envelope_sign_and_verify():
    """Test if is possible to sign manifest and signature can be verified properly."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA["ENVELOPE_1_UNSIGNED"]))
    digest_object = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication.value[0]
        .SuitDigest.to_obj()
    )
    envelope.sign(PRIVATE_KEYS["ES_256"])
    signature = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication.SuitAuthenticationSigned[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[3]
        .SuitHex
    )
    # extract r and s from signature and decode_signature
    int_sig = int.from_bytes(signature, byteorder="big")
    r = int_sig >> (32 * 8)
    s = int_sig & sum([0xFF << x * 8 for x in range(0, 32)])
    dss_signature = encode_dss_signature(r, s)
    algorithm_name = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication.SuitAuthenticationSigned[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[0]
        .SuitHeaderMap[suit_cose_algorithm_id]
        .value
    )
    cose_structure = CoseSigStructure.from_obj(
        {
            "context": "Signature1",
            "body_protected": {"suit-cose-algorithm-id": algorithm_name},
            "external_add": "",
            "payload": digest_object,
        }
    )
    binary_data = cose_structure.to_cbor()
    public_key = load_pem_private_key(PRIVATE_KEYS["ES_256"], None).public_key()
    public_key.verify(dss_signature, binary_data, ec.ECDSA(hashes.SHA256()))
