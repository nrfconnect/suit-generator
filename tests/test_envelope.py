#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for envelope.py implementation."""
import json
import os
import pathlib
import deepdiff
import pytest
from cryptography.hazmat.primitives import hashes
from suit_generator.envelope import SuitEnvelope
from suit_generator.input_output import FileTypeException

TEMP_DIRECTORY = pathlib.Path("test_test_data")

TEST_SUIT_STRING_AUTHENTICATINON_WRAPPER = (
    "d86ba2025827815824822f58206658ea560262696dd1f13b782239a064da"
    "7c6c5cbaf52fded428a6fc83c7e5af035871a50101020003585fa20281814"
    "1000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af"
    "1425695e48bf429b2d51f2ab45035824822f582000112233445566778899a"
    "abbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f07"
    "4382030f0943821702"
)

TEST_SUIT_STRING_AUTHENTICATINON_WRAPPER = (
    "d86ba2025827815824822f58206658ea560262696dd1f13b782239a064da"
    "7c6c5cbaf52fded428a6fc83c7e5af035871a50101020003585fa20281814"
    "1000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af"
    "1425695e48bf429b2d51f2ab45035824822f582000112233445566778899a"
    "abbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f07"
    "4382030f0943821702"
)

TEST_JSON_STRING_UNSIGNED = """{
    "SUIT_Envelope_Tagged":
    {
        "suit-authentication-wrapper":
        {
            "SuitDigest":
            {
                "suit-digest-algorithm-id": "cose-alg-sha-256",
                "suit-digest-bytes": "aaabbbcccdddeeefff"
            }
        },
        "suit-manifest":
        {
            "suit-manifest-version": 1,
            "suit-manifest-sequence-number": 1,
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
            "#file.bin": "file.bin"
        }
    }
}"""

TEST_JSON_STRING_SIGNED = """{
    "SUIT_Envelope_Tagged":
    {
        "suit-authentication-wrapper":
        {
            "SuitDigest":
            {
                "suit-digest-algorithm-id": "cose-alg-sha-256"
            },
            "SuitAuthenticationBlock":
            {
                "CoseSign1Tagged":
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
            "suit-manifest-sequence-number": 1,
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
            "#file.bin": "file.bin"
        }
    }
}"""


TEST_JSON_STRING_SIGNED_RAW = """{
    "SUIT_Envelope_Tagged":
    {
        "suit-authentication-wrapper":
        {
            "SuitDigest":
            {
                "suit-digest-algorithm-id": "cose-alg-sha-256"
            },
            "SuitAuthenticationBlock":
            {
                "CoseSign1Tagged":
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
            "#file.bin": "file.bin"
        }
    }
}"""


@pytest.fixture
def mocker_json_open(mocker):
    """Mock JSON file open."""
    mocked_data = mocker.mock_open(read_data=TEST_JSON_STRING_SIGNED)
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
    envelope._envelope = json.dumps(TEST_JSON_STRING_SIGNED)
    try:
        envelope.dump("some_output_json_file.json")
    except Exception:
        assert False, "Not possible to write json file from internal envelope representation."


def test_write_to_xml_auto_negative(mocker_json_open):
    """Test if not supported file extension if properly recognized."""
    envelope = SuitEnvelope()
    envelope._envelope = json.dumps(TEST_JSON_STRING_SIGNED)
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
    envelope._envelope = json.dumps(TEST_JSON_STRING_SIGNED)
    with pytest.raises(FileTypeException):
        envelope.dump("some_output_json_file.xml", output_type="xml")


def test_read_from_xml_negative(mocker_json_open):
    """Test if not supported file input_type if properly recognized."""
    envelope = SuitEnvelope()
    with pytest.raises(FileTypeException):
        envelope.load("some_json_file.xml", input_type="xml")


@pytest.fixture
def setup_and_teardown(tmp_path_factory):
    """Create and cleanup environment."""
    # Setup environment
    #   - create temp directory
    #   - create input json files
    #   - create binary file
    start_directory = os.getcwd()
    path = tmp_path_factory.mktemp(TEMP_DIRECTORY)
    os.chdir(path)
    with open("envelope_1.json", "w") as fh:
        fh.write(TEST_JSON_STRING_UNSIGNED)
    with open("envelope_2.json", "w") as fh:
        fh.write(TEST_JSON_STRING_SIGNED)
    with open("file.bin", "wb") as fh:
        fh.write(b"\xde\xad\xbe\xef")
    yield
    # Cleanup environment
    #   - remove temp directory
    os.chdir(start_directory)


@pytest.mark.parametrize("input_data", ["envelope_1", "envelope_2"])
def test_envelope_unsigned_creation(setup_and_teardown, input_data):
    envelope = SuitEnvelope()
    envelope.load(f"{input_data}.json", input_type="json")
    envelope.dump(f"{input_data}.suit", output_type="suit")


def calculate_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def test_envelope_unsigned_creation_and_parsing(setup_and_teardown):
    envelope = SuitEnvelope()
    # create envelope_1
    envelope.load("envelope_1.json", input_type="json")
    envelope.dump("envelope_1.suit", output_type="suit")
    # parse envelope_1
    envelope.load("envelope_1.suit", input_type="suit")
    envelope.dump("envelope_1_copy.json", output_type="json")
    # create envelope_1_copy based on new input json file
    envelope.load("envelope_1_copy.json", input_type="json")
    envelope.dump("envelope_1_copy.suit", output_type="suit")
    # compare create json and suit files
    with open("envelope_1.json") as fh_json_1, open("envelope_1_copy.json") as fh_json_2:
        assert deepdiff.DeepDiff(fh_json_1.read(), fh_json_2.read())
    with open("envelope_1.suit", "rb") as fh_suit_1, open("envelope_1_copy.suit", "rb") as fh_suit_2:
        assert calculate_hash(fh_suit_1.read()) == calculate_hash(fh_suit_2.read())
