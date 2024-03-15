#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for SUIT internal envelope representation."""
import pytest
import binascii

from suit_generator.suit.envelope import SuitEnvelopeTagged
from suit_generator.suit.types.keys import (
    suit_manifest,
    suit_text,
    suit_install,
    suit_payload_fetch,
)

TEST_DATA_OBJECTS = {
    "ENVELOPE_1_SEVERED_TEXT": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
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
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
                },
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
    "ENVELOPE_2_SEVERED_TEXT_MISSING_DATA": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
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
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
                },
            },
            "suit-integrated-payloads": {"#file.bin": "file.bin"},
        }
    },
    "ENVELOPE_3_SEVERED_INSTALL": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
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
                    ],
                },
                "suit-install": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
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
            "suit-integrated-payloads": {"#file.bin": "file.bin"},
        }
    },
    "ENVELOPE_4_SEVERED_FETCH": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
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
                    ],
                },
                "suit-payload-fetch": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
                },
            },
            "suit-payload-fetch": [
                {"suit-directive-set-component-index": 2},
                {"suit-directive-override-parameters": {"suit-parameter-uri": "#file.bin"}},
            ],
            "suit-integrated-payloads": {"#file.bin": "file.bin"},
        }
    },
    "ENVELOPE_5_SEVERED_INSTALL_TEXT_AND_FETCH": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
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
                    ],
                },
                "suit-install": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
                },
                "suit-payload-fetch": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
                },
                "suit-text": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
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
            "suit-payload-fetch": [
                {"suit-directive-set-component-index": 2},
                {"suit-directive-override-parameters": {"suit-parameter-uri": "#file.bin"}},
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
            "suit-integrated-payloads": {"#file.bin": "file.bin"},
        }
    },
    "ENVELOPE_6_SEVERED_INSTALL_TEXT_AND_FETCH_MISSING_INSTALL_DATA": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
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
                    ],
                },
                "suit-install": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
                },
                "suit-payload-fetch": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
                },
                "suit-text": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
                },
            },
            "suit-payload-fetch": [
                {"suit-directive-set-component-index": 2},
                {"suit-directive-override-parameters": {"suit-parameter-uri": "#file.bin"}},
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
            "suit-integrated-payloads": {"#file.bin": "file.bin"},
        }
    },
    "ENVELOPE_7_NONE_SEVERED": {
        "SUIT_Envelope_Tagged": {
            "suit-authentication-wrapper": {
                "SuitDigest": {
                    "suit-digest-algorithm-id": "cose-alg-sha-256",
                    "suit-digest-bytes": "",
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
                "suit-payload-fetch": [
                    {"suit-directive-set-component-index": 2},
                    {"suit-directive-override-parameters": {"suit-parameter-uri": "#file.bin"}},
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
            },
            "suit-integrated-payloads": {"#file.bin": "file.bin"},
        }
    },
}

TEST_BINARY_DATA = {
    "ENVELOPE_1_SEVERED_TEXT": (
        "d86ba402458143822f400358a5a501010201035857a2028384414d4218ff451a0e054000451a0005600084414"
        "d410e451a2e054000451a000560008241444100045829840c0114a201507617daa571fd5a858f94e28d735ce9"
        "f40250d622bafd4337518590bc6368cda7fbca11581e900c0214a115692366696c652e62696e150003000c011"
        "4a116021600030017822f5820aac171d7a184ecd31c01495ac6b656b2e60a5aa43de6f6d1c9acdac29bb540c2"
        "175896a162656ea184414d4102451a0e0aa000451a00056000a60178184e6f726469632053656d69636f6e647"
        "563746f7220415341026e6e5246353432305f637075617070036e6e6f7264696373656d692e636f6d04781c54"
        "6865206e524635343230206170706c69636174696f6e20636f726505781a53616d706c65206170706c6963617"
        "4696f6e20636f7265204657066676312e302e30692366696c652e62696e5820b75168e24cebca5f203ea92bd3"
        "56e60375ea18765999d1274dace20c7a81a12c"
    ),
    "ENVELOPE_2_SEVERED_TEXT_FETCH_INSTALL": (
        "d86ba602458143822f400358cea601010201035857a2028384414d4218ff451a0e054000451a0005600084414"
        "d410e451a2e054000451a000560008241444100045829840c0114a201507617daa571fd5a858f94e28d735ce9"
        "f40250d622bafd4337518590bc6368cda7fbca11822f5820f0b65173c03a9c481a0fe3ea62ed744bcfb0bef21"
        "43d4380e52dd67d5ee4200d10822f5820814a3a9e09cf691e5fa77c315c0a69a9929ee86601d5dfdca8b24819"
        "e0be745917822f5820aac171d7a184ecd31c01495ac6b656b2e60a5aa43de6f6d1c9acdac29bb540c211581e9"
        "00c0214a115692366696c652e62696e150003000c0114a11602160003001050840c0214a115692366696c652e"
        "62696e175896a162656ea184414d4102451a0e0aa000451a00056000a60178184e6f726469632053656d69636"
        "f6e647563746f7220415341026e6e5246353432305f637075617070036e6e6f7264696373656d692e636f6d04"
        "781c546865206e524635343230206170706c69636174696f6e20636f726505781a53616d706c65206170706c6"
        "9636174696f6e20636f7265204657066676312e302e30692366696c652e62696e5820b75168e24cebca5f203e"
        "a92bd356e60375ea18765999d1274dace20c7a81a12c"
    ),
}


def test_severable_digest_value():
    """Test if is possible to update digests for severable elements."""
    envelope = SuitEnvelopeTagged.from_obj(TEST_DATA_OBJECTS["ENVELOPE_1_SEVERED_TEXT"])
    envelope.update_severable_digests()
    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest]
        .SuitManifest[suit_text]
        .value.SuitDigest.SuitDigestRaw[1]
        .value.hex()
        == "aac171d7a184ecd31c01495ac6b656b2e60a5aa43de6f6d1c9acdac29bb540c2"
    )


@pytest.mark.parametrize(
    "input_envelope, expected_output_objects",
    [
        ("ENVELOPE_1_SEVERED_TEXT", [suit_text]),
        ("ENVELOPE_3_SEVERED_INSTALL", [suit_install]),
        ("ENVELOPE_4_SEVERED_FETCH", [suit_payload_fetch]),
        ("ENVELOPE_5_SEVERED_INSTALL_TEXT_AND_FETCH", [suit_text, suit_payload_fetch, suit_payload_fetch]),
    ],
)
def test_create_envelope_severed_element(input_envelope, expected_output_objects):
    """Test if is possible to update digests for severable elements."""
    envelope = SuitEnvelopeTagged.from_obj(TEST_DATA_OBJECTS[input_envelope])
    envelope.update_severable_digests()
    assert envelope._metadata.tag.name == "SUIT_Envelope_Tagged"
    assert envelope._metadata.tag.value == 107
    assert type(envelope.SuitEnvelopeTagged.value.SuitEnvelope) is dict
    for expected_output_object in expected_output_objects:
        assert (
            len(
                envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest]
                .SuitManifest[expected_output_object]
                .value.SuitDigest.SuitDigestRaw
            )
            == 2
        )
        assert (
            len(
                envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest]
                .SuitManifest[expected_output_object]
                .value.SuitDigest.SuitDigestRaw[1]
                .value
            )
            > 0
        )


@pytest.mark.parametrize(
    "input_envelope",
    [
        "ENVELOPE_2_SEVERED_TEXT_MISSING_DATA",
        "ENVELOPE_6_SEVERED_INSTALL_TEXT_AND_FETCH_MISSING_INSTALL_DATA",
    ],
)
def test_create_envelope_severed_text_missing_data(input_envelope):
    """Test if is possible to create an envelope in case of missing severable data."""
    envelope = SuitEnvelopeTagged.from_obj(TEST_DATA_OBJECTS["ENVELOPE_2_SEVERED_TEXT_MISSING_DATA"])
    assert envelope._metadata.tag.name == "SUIT_Envelope_Tagged"
    assert envelope._metadata.tag.value == 107
    assert type(envelope.SuitEnvelopeTagged.value.SuitEnvelope) is dict
    # suit-digest-bytes is equal to zero due to missing input data for digest calculation.
    # Exception for this case is not raised since it's expected behaviour in case of preparation of booting images.
    assert (
        len(
            envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest]
            .SuitManifest[suit_text]
            .value.SuitDigest.SuitDigestRaw[1]
            .value
        )
        == 0
    )


@pytest.mark.parametrize(
    "input_envelope, expected_output_objects",
    [
        ("ENVELOPE_1_SEVERED_TEXT", [suit_text]),
        ("ENVELOPE_2_SEVERED_TEXT_FETCH_INSTALL", [suit_text, suit_payload_fetch, suit_install]),
    ],
)
def test_parse_severable(input_envelope, expected_output_objects):
    "Test if is possible to parse envelope containing severable elements."
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_BINARY_DATA[input_envelope]))
    envelope.update_severable_digests()
    for expected_output_object in expected_output_objects:
        assert (
            len(
                envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest]
                .SuitManifest[expected_output_object]
                .value.SuitDigest.SuitDigestRaw
            )
            == 2
        )
        assert (
            len(
                envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest]
                .SuitManifest[expected_output_object]
                .value.SuitDigest.SuitDigestRaw[1]
                .value
            )
            > 0
        )


@pytest.mark.parametrize(
    "input_envelope",
    [
        "ENVELOPE_1_SEVERED_TEXT",
        "ENVELOPE_2_SEVERED_TEXT_FETCH_INSTALL",
    ],
)
def test_parse_severable_to_obj_to_cbor(input_envelope):
    """Test if parsed and recreated envelopes are binary equal."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_BINARY_DATA[input_envelope]))
    envelope.update_severable_digests()
    assert envelope.to_cbor().hex() == TEST_BINARY_DATA[input_envelope]


def test_create_envelope_none_severed():
    """Test if calling update_severable_digest does not brake an envelopes without severed elements."""
    envelope = SuitEnvelopeTagged.from_obj(TEST_DATA_OBJECTS["ENVELOPE_7_NONE_SEVERED"])
    envelope.update_severable_digests()
    assert envelope._metadata.tag.name == "SUIT_Envelope_Tagged"
    assert envelope._metadata.tag.value == 107
    assert type(envelope.SuitEnvelopeTagged.value.SuitEnvelope) is dict
    for expected_output_object in [suit_text, suit_install, suit_payload_fetch]:
        assert not (
            hasattr(
                envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest]
                .SuitManifest[expected_output_object]
                .value,
                "SuitDigest",
            )
        )


@pytest.mark.parametrize(
    "algorithm",
    [
        "cose-alg-shake128",
        "cose-alg-sha-384",
        "cose-alg-sha-512",
        "cose-alg-shake256",
    ],
)
def test_update_algorithm_recalculate_digest(algorithm):
    """Test if new digest is recalculated properly after algorithm change."""

    def get_digest():
        return (
            envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest]
            .SuitManifest[suit_text]
            .value.SuitDigest.SuitDigestRaw[1]
            .value
        )

    envelope = SuitEnvelopeTagged.from_obj(TEST_DATA_OBJECTS["ENVELOPE_1_SEVERED_TEXT"])
    envelope.update_severable_digests()
    digest_after_first_update = get_digest()
    envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest[
        suit_text
    ].value.SuitDigest.SuitDigestRaw[0].value = algorithm
    envelope.update_severable_digests()
    digest_after_second_update = get_digest()
    assert digest_after_first_update != digest_after_second_update


def test_update_wrong_algorithm_recalculate_digest():
    """Test if exception is raised in case of wrong algorithm."""

    envelope = SuitEnvelopeTagged.from_obj(TEST_DATA_OBJECTS["ENVELOPE_1_SEVERED_TEXT"])
    envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest[
        suit_text
    ].value.SuitDigest.SuitDigestRaw[0].value = "some-custom-algorithm"
    with pytest.raises(ValueError):
        envelope.update_severable_digests()
