#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for envelope.py implementation."""
import json
import pytest
from suit_generator.envelope import SuitEnvelope

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
        envelope.dump("some_ouptut_json_file.json")
    except Exception:
        assert False, "Not possible to write json file from internal envelope representation."
