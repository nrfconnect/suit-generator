#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for envelope.py implementation."""
import binascii
import json
import os
import pathlib
import deepdiff
import pytest
from unittest.mock import patch
from cryptography.hazmat.primitives import hashes
from suit_generator.envelope import SuitEnvelope
from suit_generator.exceptions import GeneratorError
from suit_generator.input_output import FileTypeException
from suit_generator.suit.authentication import SuitDigest, SuitAuthenticationBlock
from suit_generator.suit.types.common import Metadata, cbstr

TEMP_DIRECTORY = pathlib.Path("test_test_data")

ENVELOPE_SIGNED_TWO_TIMES = (
    "D86BA30258BF835824822F5820F429BA01A650F9430D8759CDA5F69DC75D7A389683E986576C75513BACE432D9584AD28443A1"
    "0126A0F65840149A9C4B1BDAB46F7F46A6200A7F8A46FB2BF6F4F87933E07F9D293C2894ED2F225C83744CBB60337E8858E8F1"
    "BBBCEEE2642F500A7C28B1B84EC1CD136D081D584AD28443A10126A0F65840D686E1BB235FD660B6421F1076802F93ED17034B"
    "FD7F55671F46C44C1CD32FBF0007871452EDFEAAEA0FED59885CC3DAC77B081EBA354EF0C323B0C7D03EF0DF0358B6A7010102"
    "0103586BA2028184414D4102451A0E0AA000451A000560000458548614A401507617DAA571FD5A858F94E28D735CE9F4025008"
    "C1B59955E85FBC9E767BC29CE1B04D035824822F58201C44B9A9A49B1574BB6C57BDF1F9BA44B79B32ECBB27B4EFCBEFA15652"
    "DB72E10E04010F020F074382030F094382170211528614A115692366696C652E62696E1502030F17822F5820D396652C143091"
    "C81914532F9D55D4D6BDEB8FF366AE734983CBBBC1B1E2750A692366696C652E62696E4428FAF50C"
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
                                "RFC4122_UUID": "nordicsemi.com"
                            },
                            "suit-parameter-class-identifier":
                            {
                                "raw": "d622bafd4337518590bc6368cda7fbca"
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
                                "RFC4122_UUID": "nordicsemi.com"
                            },
                            "suit-parameter-class-identifier":
                            {
                                "raw": "d622bafd4337518590bc6368cda7fbca"
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
                                "RFC4122_UUID": "nordicsemi.com"
                            },
                            "suit-parameter-class-identifier":
                            {
                                "raw": "d622bafd4337518590bc6368cda7fbca"
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
    envelope._envelope = json.loads(TEST_JSON_STRING_SIGNED)
    try:
        envelope.dump("some_output_json_file.json")
    except Exception:
        assert False, "Not possible to write json file from internal envelope representation."


def test_write_to_xml_auto_negative(mocker_json_open):
    """Test if not supported file extension if properly recognized."""
    envelope = SuitEnvelope()
    envelope._envelope = json.loads(TEST_JSON_STRING_SIGNED)
    with pytest.raises(FileTypeException):
        envelope.dump("some_output_json_file.xml")


def test_read_from_xml_auto_negative(mocker_json_open):
    """Test if not supported file exception if properly recognized."""
    envelope = SuitEnvelope()
    with pytest.raises(FileTypeException):
        envelope.load("some_json_file.xml")


def test_write_to_xml_negative(mocker_json_open):
    """Test if not supported file output_type if properly recognized."""
    envelope = SuitEnvelope()
    envelope._envelope = json.loads(TEST_JSON_STRING_SIGNED)
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
    with open("envelope_signed_twice.suit", "wb") as fh:
        fh.write(binascii.a2b_hex(ENVELOPE_SIGNED_TWO_TIMES))
    yield
    # Cleanup environment
    #   - remove temp directory
    os.chdir(start_directory)


@pytest.mark.parametrize("input_data", ["envelope_1", "envelope_2"])
def test_envelope_unsigned_creation(setup_and_teardown, input_data):
    """Test if is possible to create an envelope from input configuration file."""
    envelope = SuitEnvelope()
    envelope.load(f"{input_data}.json", input_type="json")
    envelope.dump(f"{input_data}.suit", output_type="suit")


def test_envelope_signed_twice_parsing(setup_and_teardown):
    """Test if is possible to parse an envelope signed twice."""
    envelope = SuitEnvelope()
    envelope.load("envelope_signed_twice.suit", input_type="suit")
    envelope.dump("envelope_signed_twice.yaml", output_type="yaml")


@patch(
    "suit_generator.suit.authentication.SuitAuthentication._metadata",
    Metadata(map={"SuitDigest*": cbstr(SuitDigest), "SuitAuthentication*": SuitAuthenticationBlock}),
)
def test_envelope_parsing_wrong_internal_structure_dynamic_element_twice(setup_and_teardown):
    """Test if exception is raised in case of wrong internal configuration - two dynamic elements."""
    envelope = SuitEnvelope()
    with pytest.raises(GeneratorError):
        envelope.load("envelope_signed_twice.suit", input_type="suit")


@patch(
    "suit_generator.suit.authentication.SuitAuthentication._metadata",
    Metadata(map={"SuitDigest*": cbstr(SuitDigest), "SuitAuthentication": SuitAuthenticationBlock}),
)
def test_envelope_parsing_wrong_internal_structure_dynamic_element_at_the_beginning(setup_and_teardown):
    """Test if exception is raised in case of wrong internal configuration - wrong position of dynamic element."""
    envelope = SuitEnvelope()
    with pytest.raises(GeneratorError):
        envelope.load("envelope_signed_twice.suit", input_type="suit")


def calculate_hash(data):
    """Calculate hash for passed data."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def test_envelope_unsigned_creation_and_parsing(setup_and_teardown):
    """Test if is possible to create and next parse an envelope."""
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
