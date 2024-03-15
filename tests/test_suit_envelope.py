#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for SUIT internal envelope representation."""
import pytest
import binascii

from suit_generator.suit.envelope import SuitEnvelopeTagged, SuitEnvelopeTaggedSimplified
from suit_generator.suit.types.keys import (
    suit_authentication_wrapper,
    suit_manifest,
    suit_manifest_sequence_number,
    suit_manifest_version,
    suit_common,
    suit_integrated_payloads,
)

from deepdiff import DeepDiff

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
        "768692f6a6b6c2f6d6e6f2f7072732f7475762f7778792f7a2f66696c652e62696e1502030f175901a1a16265"
        "6ea2017901727465737420656e76656c6f706520666f7220737569742d67656e657261746f722c20776974682"
        "076657279206c6f6e6720737472696e67206162636465666768696a6b6c6d6f6e6f70727374757778797a3132"
        "333435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636"
        "465666768696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f"
        "6e6f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f70727374757778797"
        "a3132333435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a31323334353637383961"
        "62636465666768696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465666768696a6b6"
        "c6d6f6e6f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f707273747577"
        "78797a3132333435363738395c6e5c6e5c6e5c6e814100a4036e6e6f7264696373656d692e636f6d046473756"
        "974056474657374066476313233"
    ),
    "ENVELOPE_3_UNSIGNED": (
        "d86ba3025827815824822f5820967fb04cc65b3bae64b716120547e07eaef68bec44823e39094ade741849ff8c"
        "03587fa701010201035839a2028181441e05400004582d8614a301507617daa571fd5a858f94e28d735ce9f402"
        "50d622bafd4337518590bc6368cda7fbca0e00010f020f074382030f0943821702114d8214a11568236170702e"
        "62696e17822f5820cf695600628b16e2b8dbecddf389c27dd82ec92ef17ce935d7de931016a3670817588ca162"
        "656ea181441e054000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246353432"
        "305f637075617070036e6e6f7264696373656d692e636f6d04781d546865206e52463533383430206170706c69"
        "636174696f6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e"
        "302e30"
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
        "702e62696e17822f58202ba46bc4a70d125b30c4227985578eb6a889807a939cc148b4d8110d4f2ed940175897a16265"
        "6ea184414d4102451a0e054000451a00056000a60178184e6f726469632053656d69636f6e647563746f722041534102"
        "6e6e5246353432305f637075617070036e6e6f7264696373656d692e636f6d04781d546865206e524635333834302061"
        "70706c69636174696f6e20636f726505781a53616d706c65206170706c69636174696f6e20636f726520465706667631"
        "2e302e30"
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
    "ENVELOPE_8_SIGNED_TWO_TIMES": (
        "D86BA40258BF835824822F5820F429BA01A650F9430D8759CDA5F69DC75D7A389683E986576C75513BACE432D9584AD28443A1"
        "0126A0F65840149A9C4B1BDAB46F7F46A6200A7F8A46FB2BF6F4F87933E07F9D293C2894ED2F225C83744CBB60337E8858E8F1"
        "BBBCEEE2642F500A7C28B1B84EC1CD136D081D584AD28443A10126A0F65840D686E1BB235FD660B6421F1076802F93ED17034B"
        "FD7F55671F46C44C1CD32FBF0007871452EDFEAAEA0FED59885CC3DAC77B081EBA354EF0C323B0C7D03EF0DF0358B6A7010102"
        "0103586BA2028184414D4102451A0E0AA000451A000560000458548614A401507617DAA571FD5A858F94E28D735CE9F4025008"
        "C1B59955E85FBC9E767BC29CE1B04D035824822F58201C44B9A9A49B1574BB6C57BDF1F9BA44B79B32ECBB27B4EFCBEFA15652"
        "DB72E10E04010F020F074382030F094382170211528614A115692366696C652E62696E1502030F17822F5820D396652C143091"
        "C81914532F9D55D4D6BDEB8FF366AE734983CBBBC1B1E2750A175896A162656EA184414D4102451A0E0AA000451A00056000A6"
        "0178184E6F726469632053656D69636F6E647563746F7220415341026E6E5246353432305F637075617070036E6E6F72646963"
        "73656D692E636F6D04781C546865206E524635343230206170706C69636174696F6E20636F726505781A53616D706C65206170"
        "706C69636174696F6E20636F7265204657066676312E302E30692366696C652E62696E4428FAF50C"
    ),
    "ENVELOPE_9_UNSIGNED_PROTECTED_KEY_ID": (
        "D86BA202581B8247822F44DEADBEEF51D28447A201260442187BA0F644DEADBEEF03584BA40101020103583EA2028184414D41"
        "02451A0E0AA000451A000560000458278214A201507617DAA571FD5A858F94E28D735CE9F40250D622BAFD4337518590BC6368"
        "CDA7FBCA074382030F"
    ),
    "ENVELOPE_10_UNSIGNED_UNPROTECTED_KEY_ID": (
        "D86BA202581C8247822F44DEADBEEF52D28443A10126A104431904D1F644DEADBEEF03584BA40101020103583EA2028184414D"
        "4102451A0E0AA000451A000560000458278214A201507617DAA571FD5A858F94E28D735CE9F40250D622BAFD4337518590BC63"
        "68CDA7FBCA074382030F"
    ),
    "ENVELOPE_11_UNSIGNED_PROTECTED_KEY_ID_TWO_AUTH_BLOCKS": (
        "D86BA202582F8347822F44DEADBEEF52D28448A2012604431904D1A0F644DEADBEEF52D28448A2012604431904D1A0F644DEAD"
        "BEEF03584BA40101020103583EA2028184414D4102451A0E0AA000451A000560000458278214A201507617DAA571FD5A858F94"
        "E28D735CE9F40250D622BAFD4337518590BC6368CDA7FBCA074382030F"
    ),
    "ENVELOPE_12_CBOR_MEMORY_ERROR_NCSDK-24195": (
        "d86ba4025827815824822f5820abe742c95d30b5d0dcc33e03cc939e563b41673cd9c6d0c6d06a5300c9af182e0358d7a80101"
        "020103586ca202818444634d454d4100451a0008000041000458568614a401507617daa571fd5a858f94e28d735ce9f402505b"
        "469fd190ee539ca318681b03695e36035824822f58209c4b47c223b27e796d430b2078322f4069ded55f3d4092180f20dec90a"
        "61c9ff0e190400010f020f074382030f094382170211528614a115692366696c652e62696e1502030f17822f582040c4a598cc"
        "3b9c6030bb008f7eb3bda61af4e7af09a83cad2eb5fae5b0517a8905824c6b494e53544c445f4d465354505b469fd190ee539c"
        "a318681b03695e36175883a162656ea18444634d454d4100451a000800004100a60178184e6f726469632053656d69636f6e64"
        "7563746f7220415341026474657374036e6e6f7264696373656d692e636f6d04745468652074657374206170706c6963617469"
        "6f6e05781b53616d706c65206170706c69636174696f6e20666f722074657374066676312e302e30692366696c652e62696e59"
        "04007709a634cd52952ec31109b6d1586c3541866ec9a34f88cc461af8ff9cce9c5552f24f635964347b50049a9da998d075fe"
        "2c927ae8e4eb092f1115cfc07b928b7fed4e694f627ff049acca5af5bb419b36a39267abe8dd43650c97da329e0a719fd9a9e9"
        "24372f270ed13b191e2125761e28187f92342d4a96fe11290162f2da03a8ecce8d914f771e4ce9f298dd50440b9df464f19391"
        "29fb1bffcceeed4195474871e2e5b7916880c3771af2c997b0731272db3fff34f0d999476a3554716915bf84ec9de84e6ce2b8"
        "b2e891cbaf418ab5121e8ccbb0b24cb403b25e8da7a68588ce00694c95e1a5150d8e37189b5b52d283b603c40b6e74ca408ae4"
        "1a08ce7fd938c539dad8ee410c5f84f566c96f4bf72f6476565ea34f9a3ac5c5e51a8a70000315447eb05b1d7e3741156e1c73"
        "8463057fbb5defe72d9d4274bf480866bf0401db047f0b247d4fb409f1ca9b3527856c30d9333812822fe2163cbdbe850e548a"
        "41c252f42a94123823f96232d8ca92cdec0d863ef4dcbd577ac62fa47688db60bc9fd2ac3d4c6df655854f67b7c46ebfaae9f6"
        "304830d364d906bbee9153d19a82ab745cb2ae64cbe72af5bf08f10a31c001f0191e55ae853178a19f7bb36f14b6ff5807c817"
        "f366bd3a7d9b3942f14082a3048738069896884737c193f18fc6b82689cc9a3a4309f8ea42e8c2b0f63e1aa0ac01c3f336df8d"
        "ab4208aa342c73c623d34740ef3fdca59bdc76c334b3831270c8cec19f15f35013774cb6f47af25240f0be1c7949dd59610b06"
        "94d41d209e81cc81986f8f9947c65563e5d0e1877dbc3efd6a96a7e1c3963dfee53fd2c05d08077afd3babe20b2d5a061d0237"
        "085d3d6541073ede5088f5b636c6ad4c8b94b20a52a645913af8d640627a7ce2998c1350c5077fb0d07ff435699c63c1238d1b"
        "0fea2b4c6d8565ee20e8de24dc7f3c8fbad5df8f6b711e93e3a34c623682a24f88bfe5323c814cf002e97209186b56215b5df7"
        "047b8f5efd5ca4864334e6d9d315d712dabe9f602850dc7bbc62a566e11587c9b88394748ec3296a2b8278659d9f6ed7fdb8bc"
        "d90b1a33b32228509fdcd42fb83ace9d6a3d85413c4c1c5a5b361d695ba14d14372faae693b70776995d112f721e2595ee4796"
        "382b2aeef18c828f8dc4eb4db33705617c7f65a9c186566021281de12b14a86a7d67be441d8f529295c7e2bd0936dfde05cab5"
        "017b9f003505fe680088e85f10acad86377cb44e1d80e4e5437e47df366b6afb721c584681fba59e6258cc5a685d07f8c83ad5"
        "c9e3e2c1b24de8c6a70436d47134c76c97b757cce27852208194f31d3806b74b949b3281fe3c669f16ba00628015acbbf1b307"
        "15012e3ed0e789b2c6a6f660d556a6f3441c29bfa6582b981c7b54252c7052c20b8f5a436415eedfb84ac742e7444dd8bfe2ea"
        "e0d084f709c2"
    ),
    "ENVELOPE_12_CBOR_MEMORY_ERROR_NCSDK-24195_2": (
        "d86ba3025827815824822f5820abe742c95d30b5d0dcc33e03cc939e563b41673cd9c6d0c6d06a5300c9af182e0358d5a80101"
        "020103586ca202818444634d454d4100451a0008000041000458568614a401507617daa571fd5a858f94e28d735ce9f402505b"
        "469fd190ee539ca318681b03695e36035824822f58209c4b47c223b27e796d430b2078322f4069ded55f3d4092180f20dec90a"
        "61c9ff0e190400010f020f074382030f094382170211528614a115692366696c652e62696e1502030f17822f582040c4a598cc"
        "3b9c6030bb008f7eb3bda61af4e7af09a83cad2eb5fae5b0517a8905824c6b494e53544c445f4d4653544e5b676a1b1b1b1b1b"
        "1b1b1ba49696175883a162656ea18444634d454d4100451a000800004100a60178184e6f726469632053656d69636f6e647563"
        "746f7220415341026474657374036e6e6f7264696373656d692e636f6d04745468652074657374206170706c69636174696f6e"
        "05781b53616d706c65206170706c69636174696f6e20666f722074657374066676312e302e30"
    ),
    "ENVELOPE_13_SHORT_ENVELOPE": (
        "d86ba2025827815824822f5820d0c5d63342e9d4d9a55ffdfa86cbd39e1b0433e3683e47d517b0f4a2334124d8035828a40101"
        "020105824c6b494e53544c445f4d46535450beefbeefbeefbeefbeefbeefbeefbeef0341a0"
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
                "en": {
                    '["M", 2, 235577344, 352256]': {
                        "suit-text-vendor-name": "Nordic Semiconductor ASA",
                        "suit-text-model-name": "nRF5420_cpuapp",
                        "suit-text-vendor-domain": "nordicsemi.com",
                        "suit-text-model-info": "The nRF5420 application core",
                        "suit-text-component-description": "Sample application core FW",
                        "suit-text-component-version": "v1.0.0",
                    }
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
                "en": {
                    '["M", 2, 235577344, 352256]': {
                        "suit-text-vendor-name": "Nordic Semiconductor ASA",
                        "suit-text-model-name": "nRF5420_cpuapp",
                        "suit-text-vendor-domain": "nordicsemi.com",
                        "suit-text-model-info": "The nRF5420 application core",
                        "suit-text-component-description": "Sample application core FW",
                        "suit-text-component-version": "v1.0.0",
                    }
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
                    "en": {
                        '["M", 2, 235577344, 352256]': {
                            "suit-text-vendor-name": "Nordic Semiconductor ASA",
                            "suit-text-model-name": "nRF5420_cpuapp",
                            "suit-text-vendor-domain": "nordicsemi.com",
                            "suit-text-model-info": "The nRF5420 application core",
                            "suit-text-component-description": "Sample application core FW",
                            "suit-text-component-version": "v1.0.0",
                        }
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
    "SUIT_ENVELOPE_BASIC_KEY_ID_PROTECTED_NO_PAYLOAD": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {"suit-digest-algorithm-id": "cose-alg-sha-256", "suit-digest-bytes": "deadbeef"},
                "SuitAuthenticationBlock": {
                    "CoseSign1Tagged": {
                        "protected": {"suit-cose-algorithm-id": "cose-alg-es-256", "suit-cose-key-id": 123},
                        "unprotected": {},
                        "payload": None,
                        "signature": "DEADBEEF",
                    },
                },
            },
            "suit-manifest": {
                "suit-manifest-version": 1,
                "suit-manifest-sequence-number": 1,
                "suit-common": {
                    "suit-components": [["M", 2, 235577344, 352256]],
                    "suit-shared-sequence": [
                        {
                            "suit-directive-override-parameters": {
                                "suit-parameter-vendor-identifier": {"RFC4122_UUID": "nordicsemi.com"},
                                "suit-parameter-class-identifier": {"raw": "d622bafd4337518590bc6368cda7fbca"},
                            }
                        }
                    ],
                },
                "suit-validate": [
                    {
                        "suit-condition-image-match": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure",
                        ]
                    }
                ],
            },
        }
    },
    "SUIT_ENVELOPE_BASIC_KEY_ID_UNPROTECTED_NO_PAYLOAD": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {"suit-digest-algorithm-id": "cose-alg-sha-256", "suit-digest-bytes": "deadbeef"},
                "SuitAuthenticationBlock": {
                    "CoseSign1Tagged": {
                        "protected": {"suit-cose-algorithm-id": "cose-alg-es-256"},
                        "unprotected": {"suit-cose-key-id": 1233},
                        "payload": None,
                        "signature": "DEADBEEF",
                    }
                },
            },
            "suit-manifest": {
                "suit-manifest-version": 1,
                "suit-manifest-sequence-number": 1,
                "suit-common": {
                    "suit-components": [["M", 2, 235577344, 352256]],
                    "suit-shared-sequence": [
                        {
                            "suit-directive-override-parameters": {
                                "suit-parameter-vendor-identifier": {"RFC4122_UUID": "nordicsemi.com"},
                                "suit-parameter-class-identifier": {"raw": "d622bafd4337518590bc6368cda7fbca"},
                            }
                        }
                    ],
                },
                "suit-validate": [
                    {
                        "suit-condition-image-match": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure",
                        ]
                    }
                ],
            },
        }
    },
    "SUIT_ENVELOPE_BASIC_KEY_ID_PROTECTED_NO_PAYLOAD_TWO_AUTH_BLOCKS": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {"suit-digest-algorithm-id": "cose-alg-sha-256", "suit-digest-bytes": "deadbeef"},
                "SuitAuthenticationBlock": {
                    "CoseSign1Tagged": {
                        "protected": {"suit-cose-algorithm-id": "cose-alg-es-256", "suit-cose-key-id": 1233},
                        "unprotected": {},
                        "payload": None,
                        "signature": "DEADBEEF",
                    }
                },
                "SuitAuthenticationBlock2": {
                    "CoseSign1Tagged": {
                        "protected": {"suit-cose-algorithm-id": "cose-alg-es-256", "suit-cose-key-id": 1233},
                        "unprotected": {},
                        "payload": None,
                        "signature": "DEADBEEF",
                    }
                },
            },
            "suit-manifest": {
                "suit-manifest-version": 1,
                "suit-manifest-sequence-number": 1,
                "suit-common": {
                    "suit-components": [["M", 2, 235577344, 352256]],
                    "suit-shared-sequence": [
                        {
                            "suit-directive-override-parameters": {
                                "suit-parameter-vendor-identifier": {"RFC4122_UUID": "nordicsemi.com"},
                                "suit-parameter-class-identifier": {"raw": "d622bafd4337518590bc6368cda7fbca"},
                            }
                        }
                    ],
                },
                "suit-validate": [
                    {
                        "suit-condition-image-match": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure",
                        ]
                    }
                ],
            },
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


TEST_YAML_ENVELOPE_AUTH_TEMPLATE = {
    """SUIT_Envelope_Tagged:
      suit-authentication-wrapper:
        SuitDigest:
          suit-digest-algorithm-id: cose-alg-sha-256
          suit-digest-bytes: deadbeef
        SuitAuthenticationBasic:
          CoseSign1Tagged:
            protected:
              suit-cose-algorithm-id: cose-alg-es-256
              suit-cose-key-id: 0x7fffffe0
            unprotected: {}
            payload: None,
            signature: DEADBEEF,
      suit-manifest:
        suit-manifest-version: 1
        suit-manifest-sequence-number: 1
        suit-common:
          suit-components:
          - - M
            - 2
            - 235577344
            - 352256
          suit-shared-sequence:
          - suit-directive-override-parameters:
              suit-parameter-vendor-identifier:
                RFC4122_UUID: nordicsemi.com
              suit-parameter-class-identifier:
                raw: d622bafd4337518590bc6368cda7fbca
              suit-parameter-image-digest:
                suit-digest-algorithm-id: cose-alg-sha-256
                suit-digest-bytes:
                  file: file.bin
              suit-parameter-image-size:
                file: file.bin
        suit-validate:
        - suit-condition-image-match:
          - suit-send-record-success
          - suit-send-record-failure
          - suit-send-sysinfo-success
          - suit-send-sysinfo-failure
      suit-integrated-payloads:
        '#file.bin': file.bin"""
}


@pytest.mark.parametrize(
    "input_envelope",
    [
        "ENVELOPE_1_UNSIGNED",
        "ENVELOPE_2_UNSIGNED",
        "ENVELOPE_3_UNSIGNED",
        "ENVELOPE_6_UNSIGNED_COMPONENT_LIST",
        "ENVELOPE_12_CBOR_MEMORY_ERROR_NCSDK-24195",
        "ENVELOPE_12_CBOR_MEMORY_ERROR_NCSDK-24195_2",
        "ENVELOPE_13_SHORT_ENVELOPE",
    ],
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


def test_parse_signed_twice_envelope():
    """Test if is possible to parse envelope signed twice."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA["ENVELOPE_8_SIGNED_TWO_TIMES"]))
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
    "input_envelope, check_integrated_payload",
    [
        ("UNSIGNED_ENVELOPE", True),
        ("SIGNED_ENVELOPE", True),
        ("SIGNED_ENVELOPE_TEXT", True),
        ("UNSIGNED_ENVELOPE_TWO_INTEGRATED_PAYLOADS", True),
        ("SUIT_ENVELOPE_BASIC_KEY_ID_PROTECTED_NO_PAYLOAD", False),
        ("SUIT_ENVELOPE_BASIC_KEY_ID_UNPROTECTED_NO_PAYLOAD", False),
        ("SUIT_ENVELOPE_BASIC_KEY_ID_PROTECTED_NO_PAYLOAD_TWO_AUTH_BLOCKS", False),
    ],
)
def test_conversion_obj_to_cbor(input_envelope, check_integrated_payload):
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
    assert (
        suit_integrated_payloads in envelope.SuitEnvelopeTagged.value.SuitEnvelope if check_integrated_payload else True
    )
    binary_envelope = envelope.to_cbor()
    hex = binary_envelope.hex()
    assert hex is not None
    envelope2 = SuitEnvelopeTagged.from_cbor(binary_envelope)
    assert binary_envelope.hex() == envelope2.to_cbor().hex()


# TODO: add test to check if obj_to_internal has keyid in the structure!


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


@pytest.mark.parametrize("input_envelope", ["ENVELOPE_1_UNSIGNED", "ENVELOPE_2_UNSIGNED", "ENVELOPE_3_UNSIGNED"])
def test_parse_unsigned_simplified_envelope_parse_and_dump(input_envelope):
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTaggedSimplified.from_cbor(binascii.a2b_hex(TEST_DATA[input_envelope]))
    assert envelope.to_cbor().hex() == TEST_DATA[input_envelope]
