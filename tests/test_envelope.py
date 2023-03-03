#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for envelope.py implementation."""
import json
import pytest
from suit_generator.envelope import SuitEnvelope
from suit_generator.input_output import FileTypeException

TEST_SUIT_STRING_AUTHENTICATINON_WRAPPER = (
    "d86ba2025827815824822f58206658ea560262696dd1f13b782239a064da"
    "7c6c5cbaf52fded428a6fc83c7e5af035871a50101020003585fa20281814"
    "1000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af"
    "1425695e48bf429b2d51f2ab45035824822f582000112233445566778899a"
    "abbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f07"
    "4382030f0943821702"
)

TEST_JSON_STRING = """{
    "SUIT_Envelope_Tagged":
    {
        "suit-authentication-wrapper":
        {
            "SUIT_Digest":
            {
                "suit-digest-algorithm-id": "cose-alg-sha-256"
            },
            "SUIT_Authentication_Block":
            {
                "COSE_Sign1_Tagged":
                {
                    "protected":
                    {
                        "suit-cose-algorithm-id": "cose-alg-es-256"
                    },
                    "unprotected":
                    {},
                    "payload": null,
                    "signature": ""
                }
            }
        },
        "suit-manifest":
        {
            "suit-manifest-version": 1,
            "suit-manifest-sequence-number":
            {
                "raw": 1
            },
            "suit-common":
            {
                "suit-components":
                [
                    [
                        "M",
                        255,
                        235225088,
                        352256
                    ],
                    [
                        "M",
                        14,
                        772096000,
                        352256
                    ],
                    [
                        "D",
                        0
                    ]
                ],
                "suit-shared-sequence":
                [
                    {
                        "suit-directive-set-component-index": 1
                    },
                    {
                        "suit-directive-override-parameters":
                        {
                            "suit-parameter-vendor-identifier":
                            {
                                "RFC4122_UUID": "nordicsemi.no"
                            },
                            "suit-parameter-class-identifier":
                            {
                                "raw": "8520ea9c515e57798b5fbdad67dec7d9"
                            }
                        }
                    },
                    {
                        "suit-condition-vendor-identifier":
                        [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure"
                        ]
                    },
                    {
                        "suit-condition-class-identifier":
                        []
                    },
                    {
                        "suit-directive-set-component-index": true
                    },
                    {
                        "suit-directive-override-parameters":
                        {
                            "suit-parameter-image-digest":
                            {
                                "suit-digest-algorithm-id": "cose-alg-sha-256",
                                "suit-digest-bytes":
                                {
                                    "file": "file.bin"
                                }
                            },
                            "suit-parameter-image-size":
                            {
                                "file": "file.bin"
                            }
                        }
                    }
                ]
            },
            "suit-install":
            [
                {
                    "suit-directive-set-component-index": 2
                },
                {
                    "suit-directive-override-parameters":
                    {
                        "suit-parameter-uri": "#file.bin"
                    }
                },
                {
                    "suit-directive-fetch":
                    []
                },
                {
                    "suit-condition-image-match":
                    []
                },
                {
                    "suit-directive-set-component-index": 1
                },
                {
                    "suit-directive-override-parameters":
                    {
                        "suit-parameter-source-component": 2
                    }
                },
                {
                    "suit-directive-copy":
                    []
                },
                {
                    "suit-condition-image-match":
                    []
                }
            ],
            "suit-validate":
            [
                {
                    "suit-directive-set-component-index": 1
                },
                {
                    "suit-condition-image-match":
                    []
                }
            ],
            "suit-load":
            [
                {
                    "suit-directive-set-component-index": 0
                },
                {
                    "suit-directive-override-parameters":
                    {
                        "suit-parameter-source-component": 1
                    }
                },
                {
                    "suit-directive-copy":
                    []
                },
                {
                    "suit-condition-image-match":
                    []
                }
            ],
            "suit-invoke":
            [
                {
                    "suit-directive-set-component-index": 0
                },
                {
                    "suit-directive-invoke":
                    []
                }
            ]
        },
        "suit-integrated-payloads":
        {
            "#file.bin": "path/to/the/file"
        }
    }
}"""


@pytest.fixture
def mocker_json_open(mocker):
    """Mock JSON file open."""
    mocked_data = mocker.mock_open(read_data=TEST_JSON_STRING)
    builtin_open = "builtins.open"
    mocker.patch(builtin_open, mocked_data)


@pytest.fixture
def mocker_suit_open(mocker):
    """Mock JSON file open."""
    mocked_data = mocker.mock_open(read_data=TEST_SUIT_STRING_AUTHENTICATINON_WRAPPER)
    builtin_open = "builtins.open"
    mocker.patch(builtin_open, mocked_data)


def test_read_from_json(mocker_json_open):
    """Test if envelope can be created from json."""
    envelope = SuitEnvelope()
    try:
        envelope.load("some_json_file.json")
    except Exception:
        assert False, "Not possible to create internal envelope representation from json."


def test_write_to_json(mocker_json_open):
    """Test if is possible to dump internal envelope representation into json."""
    envelope = SuitEnvelope()
    envelope._envelope = json.dumps(TEST_JSON_STRING)
    try:
        envelope.dump("some_output_json_file.json")
    except Exception:
        assert False, "Not possible to write json file from internal envelope representation."


def test_write_to_xml_auto_negative(mocker_json_open):
    """Test if not supported file extension if properly recognized."""
    envelope = SuitEnvelope()
    envelope._envelope = json.dumps(TEST_JSON_STRING)
    with pytest.raises(FileTypeException):
        envelope.dump("some_output_json_file.xml")


def test_read_from_xml_auto_negative(mocker_json_open):
    """est if not supported file exception if properly recognized."""
    envelope = SuitEnvelope()
    with pytest.raises(FileTypeException):
        envelope.load("some_json_file.xml")


def test_write_to_xml_negative(mocker_json_open):
    """Test if not supported file output_type if properly recognized."""
    envelope = SuitEnvelope()
    envelope._envelope = json.dumps(TEST_JSON_STRING)
    with pytest.raises(FileTypeException):
        envelope.dump("some_output_json_file.xml", output_type="xml")


def test_read_from_xml_negative(mocker_json_open):
    """Test if not supported file input_type if properly recognized."""
    envelope = SuitEnvelope()
    with pytest.raises(FileTypeException):
        envelope.load("some_json_file.xml", input_type="xml")
