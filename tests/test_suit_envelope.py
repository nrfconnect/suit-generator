#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for SUIT internal envelope representation."""
import pytest
import binascii

from suit_generator.suit.authentication import CoseSigStructure
from suit_generator.suit.envelope import SuitEnvelopeTagged, SuitEnvelopeTaggedSimplified
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
        "d86ba4025827815824822f5820294da9d7431932aea7069e86cc54135e5b7cf7e05a6e52a50fb03fd78382d1f"
        "60358bba70101020203585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe025014"
        "92af1425695e48bf429b2d51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abc"
        "deffedcba98765432100e1987d0010f020f074382030f094382170211822f5820d22368ccbad2caba0b18b329"
        "65ff4359904a8e914e5288d6777700c0f535ea2917822f582001cd94dd091d5d9a0986c43ecb93aa119fef6d7"
        "04111efe09eb4dd4a9b67037d11586f8614a1157865687474703a2f2f6578616d706c652e636f6d2f76657279"
        "2f6c6f6e672f706174682f746f2f66696c652f66696c652f3132332f3435362f3738392f6162632f6465662f6"
        "768692f6a6b6c2f6d6e6f2f7072732f7475762f7778792f7a2f66696c652e62696e1502030f1759019da20179"
        "01727465737420656e76656c6f706520666f7220737569742d67656e657261746f722c2077697468207665727"
        "9206c6f6e6720737472696e67206162636465666768696a6b6c6d6f6e6f70727374757778797a313233343536"
        "3738396162636465666768696a6b6c6d6f6e6f70727374757778797a313233343536373839616263646566676"
        "8696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f7072"
        "7374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a3132333"
        "435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465"
        "666768696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6"
        "f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a31"
        "32333435363738395c6e5c6e5c6e5c6e814100a4036e6e6f7264696373656d692e636f6d04647375697405647"
        "4657374066476313233"
    ),
    "ENVELOPE_3_UNSIGNED": (
        "d86ba3025827815824822f5820967fb04cc65b3bae64b716120547e07eaef68bec44823e39094ade741849ff8c"
        "03587fa701010201035839a2028181441e05400004582d8614a301507617daa571fd5a858f94e28d735ce9f402"
        "50d622bafd4337518590bc6368cda7fbca0e00010f020f074382030f0943821702114d8214a11568236170702e"
        "62696e17822f5820cf695600628b16e2b8dbecddf389c27dd82ec92ef17ce935d7de931016a36708175888a181"
        "441e054000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246353432305f6370"
        "75617070036e6e6f7264696373656d692e636f6d04781d546865206e52463533383430206170706c6963617469"
        "6f6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e302e30"
    ),
    "ENVELOPE_4_UNSIGNED_NEGATIVE_SEQUENCE_NUMBER": (
        "d86ba3025827815824822f5820650e145465da84115e4de59496f55016a94b9e37e30260a606e486215e4c85650"
        "35883a70101023a075bcd14035839a2028181441e05400004582d8614a301507617daa571fd5a858f94e28d735c"
        "e9f40250d622bafd4337518590bc6368cda7fbca0e00010f020f074382030f0943821702114d8214a1156823617"
        "0702e62696e17822f5820cf695600628b16e2b8dbecddf389c27dd82ec92ef17ce935d7de931016a36708175888"
        "a181441e054000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246353432305f6"
        "37075617070036e6e6f7264696373656d692e636f6d04781d546865206e52463533383430206170706c69636174"
        "696f6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e302e30"
    ),
    "ENVELOPE_5_SIGNED": (
        "d86ba2025873825824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af584ad2"
        "8443a10126a0f65840e3505f7ab70bd3a0e04916f37b0d7251aa6f52ca12c7edaa886a4129a298ca6a1ecc2a57955c6b"
        "f4ccb9f01d684d5d1c4774dffbe508a034431feafa60848a2c035871a50101020003585fa202818141000458568614a4"
        "0150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45035824822f58200011223344"
        "5566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f074382030f0943821702"
    ),
    "ENVELOPE_6_UNSIGNED_COMPONENT_LIST": (
        "d86ba3025827815824822f582071395a66f9cb583dbdc797ad6cd5d101531b14c082802b491c5c6745774c748003588a"
        "a701010201035844a2028184414d4102451a0e054000451a0005600004582d8614a301507617daa571fd5a858f94e28d"
        "735ce9f40250d622bafd4337518590bc6368cda7fbca0e00010f020f074382030f0943821702114d8214a11568236170"
        "702e62696e17822f58202ba46bc4a70d125b30c4227985578eb6a889807a939cc148b4d8110d4f2ed940175893a18441"
        "4d4102451a0e054000451a00056000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246"
        "353432305f637075617070036e6e6f7264696373656d692e636f6d04781d546865206e52463533383430206170706c69"
        "636174696f6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e302e30"
    ),
    "ENVELOPE_7_UNSIGNED_TWO_INTEGRATED_PAYLOADS": (
        "D86BA4025827815824822F582087EC80F16398B14294B0978D507DB9E4FF23C00463C072762B32D4A30212CCFA0359010FA601"
        "0102050358B4A2028384414D4102451A1E0AA000451A0007F800824144410084414D4103451A1E054000451A00055800045887"
        "900C0014A201507617DAA571FD5A858F94E28D735CE9F40250D622BAFD4337518590BC6368CDA7FBCA010F020F0CF514A20358"
        "24822F5820374708FFF7719DD5979EC875D56CD2286F6D3CF7EC317A3B25632AAB28EC37BB0E100C0214A2035824822F582037"
        "4708FFF7719DD5979EC875D56CD2286F6D3CF7EC317A3B25632AAB28EC37BB0E100749880C00030F0C02030F0949880C021702"
        "0C00170211583A981E0C0114A11568236170702E62696E1502030F0C0014A116011602030F0C0114A1156A23726164696F2E62"
        "696E15020C0214A116011602030F68236170702E62696E50000000000000000000000000000000006A23726164696F2E62696E"
        "5000000000000000000000000000000000"
    ),
}

TEST_DATA_OBJECTS = {
    "UNSIGNED_ENVELOPE": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "aaabbbcccdddeeefff",
                },
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
                    "suit-dependencies": {
                        "0": {},
                        "1": {
                            "suit-dependency-prefix": ["M", 1234],
                        },
                    },
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
                    {
                        "suit-directive-run-sequence": [
                            {"suit-directive-copy": []},
                            {"suit-condition-image-match": []},
                        ]
                    },
                ],
                "suit-invoke": [{"suit-directive-set-component-index": 0}, {"suit-directive-invoke": []}],
                "suit-dependency-resolution": [
                    {"suit-condition-is-dependency": []},
                    {"suit-condition-dependency-integrity": []},
                    {"suit-directive-process-dependency": []},
                    {
                        "suit-directive-try-each": [
                            [
                                {"suit-condition-is-dependency": []},
                                {"suit-condition-dependency-integrity": []},
                                {"suit-directive-process-dependency": []},
                            ],
                            [],
                        ]
                    },
                ],
                "suit-manifest-component-id": [
                    "I",
                    {"RFC4122_UUID": {"namespace": "nordicsemi.com", "name": "nRF54H20_sample_root"}},
                ],
            },
            "suit-text": {
                '["M", 2, 235577344, 352256]': {
                    "suit-text-vendor-name": "Nordic Semiconductor ASA",
                    "suit-text-model-name": "nRF5420_cpuapp",
                    "suit-text-vendor-domain": "nordicsemi.com",
                    "suit-text-model-info": "The nRF5420 application core",
                    "suit-text-component-description": "Sample application core FW",
                    "suit-text-component-version": "v1.0.0",
                }
            },
            "suit-integrated-payloads": {"#file.bin": "file.bin"},
        }
    },
    "UNSIGNED_ENVELOPE_TWO_INTEGRATED_PAYLOADS": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "aaabbbcccdddeeefff",
                },
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
                    "suit-text-vendor-domain": "nordicsemi.com",
                    "suit-text-model-info": "The nRF5420 application core",
                    "suit-text-component-description": "Sample application core FW",
                    "suit-text-component-version": "v1.0.0",
                }
            },
            "suit-integrated-payloads": {"#file.bin": "file.bin", "#file2.bin": "file.bin"},
        }
    },
    "SIGNED_ENVELOPE": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
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
            "suit-manifest": {
                "suit-manifest-version": 1,
                "suit-manifest-sequence-number": 1,
                "suit-common": {
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
            "suit-integrated-payloads": {"#file.bin": "file.bin"},
        }
    },
    "SIGNED_ENVELOPE_TEXT": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
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
            "suit-manifest": {
                "suit-manifest-version": 1,
                "suit-manifest-sequence-number": 1,
                "suit-common": {
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
                "suit-text": {
                    '["M", 2, 235577344, 352256]': {
                        "suit-text-vendor-name": "Nordic Semiconductor ASA",
                        "suit-text-model-name": "nRF5420_cpuapp",
                        "suit-text-vendor-domain": "nordicsemi.com",
                        "suit-text-model-info": "The nRF5420 application core",
                        "suit-text-component-description": "Sample application core FW",
                        "suit-text-component-version": "v1.0.0",
                    }
                },
                "suit-validate": [{"suit-directive-set-component-index": 1}, {"suit-condition-image-match": []}],
                "suit-load": [
                    {"suit-directive-set-component-index": 0},
                    {"suit-directive-override-parameters": {"suit-parameter-source-component": 1}},
                    {"suit-directive-copy": []},
                    {"suit-condition-image-match": []},
                ],
                "suit-invoke": [{"suit-directive-set-component-index": 0}, {"suit-directive-invoke": []}],
            },
            "suit-integrated-payloads": {"#file.bin": "file.bin"},
        }
    },
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
        .SuitAuthentication[0]
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
        .SuitAuthentication[0]
        .SuitDigest.SuitDigestRaw[0]
        .SuitCoseHashAlg
        == "cose-alg-sha-256"
    )
    for required_item in [suit_manifest_sequence_number, suit_manifest_version, suit_common]:
        assert required_item in envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest.keys()


@pytest.mark.parametrize(
    "input_envelope",
    [
        "UNSIGNED_ENVELOPE",
        "SIGNED_ENVELOPE",
        "SIGNED_ENVELOPE_TEXT",
        "UNSIGNED_ENVELOPE_TWO_INTEGRATED_PAYLOADS",
    ],
)
def test_conversion_obj_to_cbor(input_envelope):
    """Test if is possible to convert object to cbor."""
    envelope = SuitEnvelopeTagged.from_obj(TEST_DATA_OBJECTS[input_envelope])
    assert type(envelope.SuitEnvelopeTagged.value.SuitEnvelope) is dict
    assert suit_authentication_wrapper in envelope.SuitEnvelopeTagged.value.SuitEnvelope.keys()
    assert suit_manifest in envelope.SuitEnvelopeTagged.value.SuitEnvelope.keys()
    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[0]
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
    envelope = SuitEnvelopeTagged.from_obj(TEST_DATA_OBJECTS["UNSIGNED_ENVELOPE"])
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
    assert "raw" in suit_obj["SUIT_Envelope_Tagged"]["suit-manifest"]["suit-manifest-component-id"][1]
    assert (
        "3f6a3a4dcdfa58c5accef9f584c41124"
        == suit_obj["SUIT_Envelope_Tagged"]["suit-manifest"]["suit-manifest-component-id"][1]["raw"]
    )
    # exclude suit-integrated-payloads, suit-parameter-vendor-identifier and suit-parameter-image-size
    # due to expected different output structure
    diff = DeepDiff(
        TEST_DATA_OBJECTS["UNSIGNED_ENVELOPE"],
        suit_obj,
        exclude_paths=[
            "root['SUIT_Envelope_Tagged']['suit-integrated-payloads']",
            "root['SUIT_Envelope_Tagged']['suit-manifest']['suit-common']['suit-shared-sequence'][1]"
            "['suit-directive-override-parameters']['suit-parameter-vendor-identifier']",
            "root['SUIT_Envelope_Tagged']['suit-manifest']['suit-common']['suit-shared-sequence'][5]"
            "['suit-directive-override-parameters']['suit-parameter-image-size']",
            "root['SUIT_Envelope_Tagged']['suit-manifest']['suit-manifest-component-id'][1]",
        ],
    )
    assert diff == {}


def test_conversion_obj_to_cbor_to_obj():
    """Test if is possible to convert object to cbor to object."""
    envelope = SuitEnvelopeTagged.from_obj(TEST_DATA_OBJECTS["UNSIGNED_ENVELOPE"])
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
    assert "raw" in suit_obj["SUIT_Envelope_Tagged"]["suit-manifest"]["suit-manifest-component-id"][1]
    assert (
        "3f6a3a4dcdfa58c5accef9f584c41124"
        == suit_obj["SUIT_Envelope_Tagged"]["suit-manifest"]["suit-manifest-component-id"][1]["raw"]
    )
    # exclude suit-integrated-payloads, suit-parameter-vendor-identifier and suit-parameter-image-size
    # due to expected different output structure
    diff = DeepDiff(
        TEST_DATA_OBJECTS["UNSIGNED_ENVELOPE"],
        suit_obj,
        exclude_paths=[
            "root['SUIT_Envelope_Tagged']['suit-integrated-payloads']",
            "root['SUIT_Envelope_Tagged']['suit-integrated-dependencies']",
            "root['SUIT_Envelope_Tagged']['suit-manifest']['suit-common']['suit-shared-sequence'][1]"
            "['suit-directive-override-parameters']['suit-parameter-vendor-identifier']",
            "root['SUIT_Envelope_Tagged']['suit-manifest']['suit-common']['suit-shared-sequence'][5]"
            "['suit-directive-override-parameters']['suit-parameter-image-size']",
            "root['SUIT_Envelope_Tagged']['suit-manifest']['suit-manifest-component-id'][1]",
        ],
    )
    assert diff == {}


def test_conversion_obj_to_cbor_to_obj_to_cbor():
    """Test if is possible to convert object to cbor to object to cbor."""
    binary_envelope = SuitEnvelopeTagged.from_obj(TEST_DATA_OBJECTS["UNSIGNED_ENVELOPE"]).to_cbor()
    suit_obj = SuitEnvelopeTagged.from_cbor(binary_envelope).to_obj()
    binary_envelope_2 = SuitEnvelopeTagged.from_obj(suit_obj).to_cbor()
    assert binary_envelope_2.hex() == binary_envelope.hex()


def test_digest_update():
    """Test if is possible to update digest."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA["ENVELOPE_1_UNSIGNED"]))
    digest_bytes_before_update = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[0]
        .SuitDigest.SuitDigestRaw[1]
        .value
    )
    envelope.update_digest()
    digest_bytes_after_update = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[0]
        .SuitDigest.SuitDigestRaw[1]
        .value
    )
    assert digest_bytes_after_update == digest_bytes_before_update


def test_digest_update_after_value_change():
    """Test if is possible to update digest."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA["ENVELOPE_1_UNSIGNED"]))
    digest_bytes_before_update = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[0]
        .SuitDigest.SuitDigestRaw[1]
        .value
    )
    envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest[
        suit_manifest_sequence_number
    ].SuitUint = 123
    envelope.update_digest()
    digest_bytes_after_update = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[0]
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
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper].SuitAuthentication[1],
        "SuitAuthenticationBlock",
    )
    assert len(envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper].SuitAuthentication) == 2
    assert hasattr(
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper].SuitAuthentication[0],
        "SuitDigest",
    )


@pytest.mark.parametrize(
    "input_data, amount_of_payloads",
    [("ENVELOPE_6_UNSIGNED_COMPONENT_LIST", 0), ("ENVELOPE_7_UNSIGNED_TWO_INTEGRATED_PAYLOADS", 2)],
)
def test_envelope_sign_and_verify(input_data, amount_of_payloads):
    """Test if is possible to sign manifest and signature can be verified properly."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA[input_data]))
    if amount_of_payloads > 0:
        assert (
            len(envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_integrated_payloads].SuitIntegratedPayloadMap)
            == amount_of_payloads
        )
    digest_object = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[0]
        .SuitDigest.to_obj()
    )
    envelope.sign(PRIVATE_KEYS["ES_256"])
    signature = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[1]
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
        .SuitAuthentication[1]
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


@pytest.mark.parametrize("input_envelope", ["ENVELOPE_1_UNSIGNED", "ENVELOPE_2_UNSIGNED", "ENVELOPE_3_UNSIGNED"])
def test_parse_unsigned_simplified_envelope_parse_and_dump(input_envelope):
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTaggedSimplified.from_cbor(binascii.a2b_hex(TEST_DATA[input_envelope]))
    assert envelope.to_cbor().hex() == TEST_DATA[input_envelope]


@pytest.mark.parametrize(
    "input_data, amount_of_payloads",
    [("ENVELOPE_6_UNSIGNED_COMPONENT_LIST", 0), ("ENVELOPE_7_UNSIGNED_TWO_INTEGRATED_PAYLOADS", 2)],
)
def test_simplified_envelope_sign_and_verify(input_data, amount_of_payloads):
    """Test if is possible to sign manifest and signature can be verified properly."""
    envelope = SuitEnvelopeTaggedSimplified.from_cbor(binascii.a2b_hex(TEST_DATA[input_data]))
    if amount_of_payloads > 0:
        assert (
            len(
                envelope.SuitEnvelopeTaggedSimplified.value.SuitEnvelopeSimplified[
                    suit_integrated_payloads
                ].SuitIntegratedPayloadMap
            )
            == amount_of_payloads
        )
    digest_object = (
        envelope.SuitEnvelopeTaggedSimplified.value.SuitEnvelopeSimplified[suit_authentication_wrapper]
        .SuitAuthentication[0]
        .SuitDigest.to_obj()
    )
    envelope.sign(PRIVATE_KEYS["ES_256"])
    signature = (
        envelope.SuitEnvelopeTaggedSimplified.value.SuitEnvelopeSimplified[suit_authentication_wrapper]
        .SuitAuthentication[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[3]
        .SuitHex
    )
    # extract r and s from signature and decode_signature
    int_sig = int.from_bytes(signature, byteorder="big")
    r = int_sig >> (32 * 8)
    s = int_sig & sum([0xFF << x * 8 for x in range(0, 32)])
    dss_signature = encode_dss_signature(r, s)
    algorithm_name = (
        envelope.SuitEnvelopeTaggedSimplified.value.SuitEnvelopeSimplified[suit_authentication_wrapper]
        .SuitAuthentication[1]
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
