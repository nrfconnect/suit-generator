#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for envelope_api.py implementation."""

import pathlib
import pytest
import binascii
from suit_generator.envelope import SuitEnvelope

TEST_DATA = {
    "ENVELOPE_1_UNSIGNED": {
        "filename": "some_envelope.suit",
        "input": (
            "d86ba2025827815824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af035871a50101"
            "020003585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2"
            "ab45035824822f582000112233445566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f0743"
            "82030f0943821702"
        ),
        "sequence-number": 0,
        "manifest-version": 1,
        "digest": "6658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af",
        "digest-algorithm": "cose-alg-sha-256",
        "manifest-component-id": None,
    },
    "ENVELOPE_2_UNSIGNED": {
        "filename": "some_envelope.suit",
        "input": (
            "d86ba2025827815824822f5820deadbeef0262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af035881a501c2"
            "4b5be8b167172ab176783ed2021a05f5e1ea03585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe"
            "02501492af1425695e48bf429b2d51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abcdeffedc"
            "ba98765432100e1987d0010f020f074382030f0943821702"
        ),
        "sequence-number": 100000234,
        "manifest-version": 111111111111111111234567890,
        "digest": "deadbeef0262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af",
        "digest-algorithm": "cose-alg-sha-256",
        "manifest-component-id": None,
    },
    "ENVELOPE_3_SIGNED_WITH_KEY_ID": {
        "filename": "some_envelope.suit",
        "input": (
            "d86ba202587a825824822f5820deadbeef0262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af5851d2844aa2"
            "012604451a7fffffe0a0f6584097eddead55e086f3a1ffc7af855383839b125bd9b6623a3e6bdc5a69863cc427f718d96d78bf"
            "3ca925154e729d308fb413101d5e11f1528859c1c369885bba77035881a501c24b5be8b167172ab176783ed2021a05f5e1ea03"
            "585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab4503"
            "5824822f582000112233445566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f074382030f"
            "0943821702"
        ),
        "sequence-number": 100000234,
        "manifest-version": 111111111111111111234567890,
        "digest": "deadbeef0262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af",
        "digest-algorithm": "cose-alg-sha-256",
        "manifest-component-id": None,
    },
    "ENVELOPE_4_SIGNED_TWO_TIMES": {
        "filename": "some_envelope.suit",
        "input": (
            "D86BA30258BF835824822F5820F429BA01A650F9430D8759CDA5F69DC75D7A389683E986576C75513BACE432D9584AD28443A1"
            "0126A0F65840149A9C4B1BDAB46F7F46A6200A7F8A46FB2BF6F4F87933E07F9D293C2894ED2F225C83744CBB60337E8858E8F1"
            "BBBCEEE2642F500A7C28B1B84EC1CD136D081D584AD28443A10126A0F65840D686E1BB235FD660B6421F1076802F93ED17034B"
            "FD7F55671F46C44C1CD32FBF0007871452EDFEAAEA0FED59885CC3DAC77B081EBA354EF0C323B0C7D03EF0DF0358B6A7010102"
            "0103586BA2028184414D4102451A0E0AA000451A000560000458548614A401507617DAA571FD5A858F94E28D735CE9F4025008"
            "C1B59955E85FBC9E767BC29CE1B04D035824822F58201C44B9A9A49B1574BB6C57BDF1F9BA44B79B32ECBB27B4EFCBEFA15652"
            "DB72E10E04010F020F074382030F094382170211528614A115692366696C652E62696E1502030F17822F5820D396652C143091"
            "C81914532F9D55D4D6BDEB8FF366AE734983CBBBC1B1E2750A692366696C652E62696E4428FAF50C"
        ),
        "sequence-number": 1,
        "manifest-version": 1,
        "digest": "f429ba01a650f9430d8759cda5f69dc75d7a389683e986576c75513bace432d9",
        "digest-algorithm": "cose-alg-sha-256",
        "manifest-component-id": None,
    },
    "ENVELOPE_5_WITH_MANIFEST_COMPONENT_ID": {
        "filename": "some_envelope.suit",
        "input": (
            "d86ba2025827815824822f5820132447d4c398cc4730e28757ac121906e59d6e2bd65bd6912cc776cf17c4f3dc0358cca80101"
            "020103586da2028184414d4102451a0e0aa000451a0007f8000458568614a401507617daa571fd5a858f94e28d735ce9f40250"
            "08c1b59955e85fbc9e767bc29ce1b04d035824822f582056e49482887e2fc2e26d42a2988ea9ddadefc2722bd8669b6f01ca6b"
            "d0e906db0e190400010f020f074382030f094382170211518614a11568236170702e62696e1502030f17822f5820749fcad1ce"
            "af7331328a046dbdf8c76b9f515931154c54087cf057f43e0ef59f058241495008c1b59955e85fbc9e767bc29ce1b04d"
        ),
        "sequence-number": 1,
        "manifest-version": 1,
        "digest": "132447d4c398cc4730e28757ac121906e59d6e2bd65bd6912cc776cf17c4f3dc",
        "digest-algorithm": "cose-alg-sha-256",
        "manifest-component-id": ["I", {"raw": "08c1b59955e85fbc9e767bc29ce1b04d"}],
    },
    "ENVELOPE_6_YAML_SIGNATURE_HARDCODED_NO_COMPONENT_ID": {
        "filename": "some_envelope.yaml",
        "input": """SUIT_Envelope_Tagged:
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
            payload: None
            signature: DEADBEEF
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
        """,
        "sequence-number": 1,
        "manifest-version": 1,
        "digest": "deadbeef",
        "digest-algorithm": "cose-alg-sha-256",
        "manifest-component-id": None,
    },
    "ENVELOPE_7_YAML_NO_SIGNATURE_COMPONENT_ID_AVAILABLE": {
        "filename": "some_envelope.yaml",
        "input": """SUIT_Envelope_Tagged:
      suit-authentication-wrapper:
        SuitDigest:
          suit-digest-algorithm-id: cose-alg-sha-256
          suit-digest-bytes: deadbeef
      suit-manifest:
        suit-manifest-version: 1
        suit-manifest-sequence-number: 1234567890
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
        suit-manifest-component-id:
            - INSTLD_MFST
            - RFC4122_UUID:
                namespace: nordicsemi.com
                name: nRF54H20_sample_rad
        """,
        "sequence-number": 1234567890,
        "manifest-version": 1,
        "digest": "deadbeef",
        "digest-algorithm": "cose-alg-sha-256",
        "manifest-component-id": [
            "INSTLD_MFST",
            {"RFC4122_UUID": {"namespace": "nordicsemi.com", "name": "nRF54H20_sample_rad"}},
        ],
    },
}


@pytest.mark.parametrize(
    "input_data",
    [
        "ENVELOPE_1_UNSIGNED",
        "ENVELOPE_2_UNSIGNED",
        "ENVELOPE_3_SIGNED_WITH_KEY_ID",
        "ENVELOPE_4_SIGNED_TWO_TIMES",
        "ENVELOPE_5_WITH_MANIFEST_COMPONENT_ID",
        "ENVELOPE_6_YAML_SIGNATURE_HARDCODED_NO_COMPONENT_ID",
        "ENVELOPE_7_YAML_NO_SIGNATURE_COMPONENT_ID_AVAILABLE",
    ],
)
def test_envelope_api_number(mocker, input_data):
    """Test if envelope can be created from json."""
    if pathlib.Path(TEST_DATA[input_data]["filename"]).suffix == ".suit":
        mocked_data = mocker.mock_open(read_data=binascii.a2b_hex(TEST_DATA[input_data]["input"]))
    else:
        mocked_data = mocker.mock_open(read_data=TEST_DATA[input_data]["input"])
    builtin_open = "builtins.open"
    mocker.patch(builtin_open, mocked_data)
    envelope = SuitEnvelope()
    envelope.load(TEST_DATA[input_data]["filename"])
    assert envelope.sequence_number == TEST_DATA[input_data]["sequence-number"]
    assert envelope.manifest_version == TEST_DATA[input_data]["manifest-version"]
    assert envelope.digest_bytes == TEST_DATA[input_data]["digest"]
    assert envelope.digest_algorithm == TEST_DATA[input_data]["digest-algorithm"]
    assert envelope.manifest_component_id == TEST_DATA[input_data]["manifest-component-id"]
