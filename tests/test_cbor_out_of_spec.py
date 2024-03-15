#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for parsing invalid inputs."""
import binascii
import pytest
import yaml
from jinja2 import Environment, BaseLoader


from suit_generator.suit.envelope import SuitEnvelopeTagged
from suit_generator.suit.manifest import (
    SuitIndex,
    SuitComponentIdentifierPart,
    SuitCommand,
    SuitSeverableCommandSequence,
    SuitSeverableText,
)

INPUT_YAML_JINJA = """SUIT_Envelope_Tagged:
  suit-authentication-wrapper:
    SuitDigest:
      suit-digest-algorithm-id: cose-alg-sha-256
      suit-digest-bytes: abe742c95d30b5d0dcc33e03cc939e563b41673cd9c6d0c6d06a5300c9af182e
  suit-manifest:
    suit-manifest-version: 1
    suit-manifest-sequence-number: 1
    suit-common:
      suit-components:
      - - MEM
        - 0
        - 524288
        - 0
      suit-shared-sequence:
      - suit-directive-override-parameters:
          suit-parameter-vendor-identifier:
            raw: {{suit_parameter_vendor|default("7617daa571fd5a858f94e28d735ce9f4")}}
          suit-parameter-class-identifier:
            raw: {{suit_parameter_identifier|default("5b469fd190ee539ca318681b03695e36")}}
          suit-parameter-image-digest:
            suit-digest-algorithm-id: cose-alg-sha-256
            suit-digest-bytes: 9c4b47c223b27e796d430b2078322f4069ded55f3d4092180f20dec90a61c9ff
          suit-parameter-image-size:
            raw: 1024
    suit-text:
      suit-digest-algorithm-id: cose-alg-sha-256
      suit-digest-bytes: 40c4a598cc3b9c6030bb008f7eb3bda61af4e7af09a83cad2eb5fae5b0517a89
    suit-manifest-component-id:
    - INSTLD_MFST
    - raw: {{suit_manifest_component_id}}
  suit-text:
    en:
      '["MEM", 0, 524288, 0]':
        suit-text-vendor-name: test vendor
        suit-text-model-name: test model name
        suit-text-vendor-domain: vendor.domain.example
        suit-text-model-info: test model
        suit-text-component-description: test component description
        suit-text-component-version: test component version
"""

CBOR_TEST_DATA = {
    # Cbor tag (37 - Binary UUID) containing unsigned integer instead of valid UUID bytes.
    #     Header: 11011000 (Major type: 110, Additional info: 11000)
    #     Major type: 6 (tag of number N/1 data item, tag info (37): byte string/Binary UUID)
    #     Payload value: b'\x00\x10`\x00\x00\x00`\x10\x00\x00\x00\x00\x00\x00' (hex:0010600000006010000000000000)
    #         *** nested cbor object ***
    #         Header: 00000000 (Major type: 000, Additional info: 00000)
    #         Major type: 0 (unsigned integer N/-)
    #         Additional information: 0
    #         Payload value: 0
    "CBOR_TAG_BROKEN_UUID": "d8250010600000006010000000000000",
    # Cbor tag (1 - Epoch-based data/time) containing unsigned integer without of spec time value.
    #     Header: 11000001 (Major type: 110, Additional info: 00001)
    #     Major type: 6 (tag of number N/1 data item, tag info (1): integer or float/Epoch-based date/time)
    #         *** nested cbor object ***
    #         Header: 00011011 (Major type: 000, Additional info: 11011)
    #         Major type: 0 (unsigned integer N/-)
    #         Additional information: 27
    #         Payload value: b'\x9b\x9b\x9b\x00\x00\x00\x00\x00' (hex:9b9b9b0000000000)
    "CBOR_TAG_BROKEN_EPOCH_TIME": "c11b9b9b9b0000000000000000000000",
    # Cbor tag (1 - Epoch-based data/time) containing unsigned integer without of spec time value.
    #     Header: 11000001 (Major type: 110, Additional info: 00001)
    #     Major type: 6 (tag of number N/1 data item, tag info (1): integer or float/Epoch-based date/time)
    #         *** nested cbor object ***
    #         Header: 00011011 (Major type: 000, Additional info: 11011)
    #         Major type: 0 (unsigned integer N/-)
    #         Additional information: 27
    #         Payload length: 8
    #         Payload value: b'\x16\x16\x16\x16\x16\x16\x16\x16' (hex:1616161616161616)
    "CBOR_TAG_BROKEN_EPOCH_TIME_2": "c11b1616161616161616161616161616",
    # Cbor tag (30 - array/Rational number containing invalid array).
    #     Header: 11011000 (Major type: 110, Additional info: 11000)
    #     Major type: 6 (tag of number N/1 data item, tag info (30): array/Rational number)
    #         *** nested cbor object ***
    #         Header: 10000100 (Major type: 100, Additional info: 00100)
    #         Major type: 4 (array/N data items (elements))
    #         Additional information: 4
    #         Payload value: b'\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00' (hex:ffffffff000000000000000000)
    "CBOR_TAG_BROKEN_ARRAY": "d81e84ffffffff000000000000000000",
    # Cbor array containing two elements: negative integer and string with extremely payload length defined.
    #     Header: 10010101 (Major type: 100, Additional info: 10101)
    #     Major type: 4 (array/N data items (elements))
    #         *** nested cbor object number 1 ***
    #         Header: 00111001 (Major type: 001, Additional info: 11001)
    #         Major type: 1 (negative integer -1-N/-)
    #         Additional information: 25
    #         Payload length: 2
    #         Payload value: b';{' (hex:3b7b)
    #         *** nested cbor object number 2 ***
    #         Header: 01111011 (Major type: 011, Additional info: 11011)
    #         Major type: 3 (text string/N bytes (UTF-8 text))
    #         Additional information: 27
    #         Payload length: 8897841259083430779
    #         Payload value: None
    "CBOR_HUGE_ELEMENT_IN_ARRAY": "95393b7b7b7b7b7b7b7b7b7b7b7b7b7b",
    # Cbor tag with invalid utf-8 string.
    #     Header: 11011000 (Major type: 110, Additional info: 11000)
    #     Major type: 6 (tag of number N/1 data item, tag info (35): UTF-8 string/Regular expression)
    #         *** nested cbor object ***
    #         Header: 01000001 (Major type: 010, Additional info: 00001)
    #         Major type: 2 (byte string/N bytes)
    #         Additional information: 1
    #         Payload length: 1
    #         Payload value: b')' (hex:29)
    "CBOR_UTF-8_OUT_OF_SPEC": "d8234129000000000000000000000000",
    # Not allowed sequence - break marker
    "CBOR_NOT_ALLOWED_SEQUENCE": "ffffffffffffffffffffffffffffffff",
    # Cbor byte string - huge payload length encoded in header.
    #     Header: 01011011 (Major type: 010, Additional info: 11011)
    #     Major type: 2 (byte string/N bytes)
    #     Additional information: 27
    #     Payload length: 17433416496376180719
    #     Payload value: None
    "CBOR_HUGE_BYTE_STRING": "5bf1efefefefefefef0000",
    # Cbor utf-8 string - huge payload length encoded in header.
    #     Header: 01111011 (Major type: 011, Additional info: 11011)
    #     Major type: 3 (text string/N bytes (UTF-8 text))
    #     Additional information: 27
    #     Payload length: 17433416496376180719
    #     Payload value: None
    "CBOR_HUGE_UTF-8_STRING": "7bf1efefefefefefef0000",
    # Cbor utf-8 infinitive string.
    #     Header: 01011111 (Major type: 010, Additional info: 11111)
    #     Major type: 2 (byte string/N bytes)
    #     Additional information: 31
    "CBOR_INFINITIVE_BYTE_STRING": "5F40FF",
    # Incorrectly encoded NaN value.
    #     Header: 11111001 (Major type: 111, Additional info: 11001)
    #     Major type: 7 (simple/float/-)
    #     Additional information: 25
    #     Payload length: 2
    #     Payload value: b'~\x00' (hex:7e00)
    "CBOR_INCORRECTLY_ENCODED_NAN": "F97E00",
    # Incorrectly formed double-precision float (type 7).
    #     Header: 11111011 (Major type: 111, Additional info: 11011)
    #     Major type: 7 (simple/float/-)
    #     Additional information: 27
    #     Payload length: 8
    #     Payload value: b'\x7f\xf0\x00\x00\x00\x00\x00\x00' (hex:7ff0000000000000)
    "CBOR_INCORRECTLY_FORMED_DOUBLE_PRECISION_FLOAT": "FB7FF0000000000000",
    # Type 7, reserved count field value (24)
    #     Header: 11111000 (Major type: 111, Additional info: 11000)
    #     Major type: 7 (simple/float/-)
    #     Additional information: 24
    "CBOR_TYPE_7_COUNT_24": "F800",
    # Type 7, reserved count field value (28)
    #     Header: 11111100 (Major type: 111, Additional info: 11100)
    #     Major type: 7 (simple/float/-)
    #     Additional information: 28
    "CBOR_TYPE_7_COUNT_28": "FC00",
    # Type 7, reserved count field value (29)
    #     Header: 11111101 (Major type: 111, Additional info: 11101)
    #     Major type: 7 (simple/float/-)
    #     Additional information: 29
    "CBOR_TYPE_7_COUNT_29": "FD000000",
    # Type 7, reserved count field value (30)
    #     Header: 11111110 (Major type: 111, Additional info: 11110)
    #     Major type: 7 (simple/float/-)
    #     Additional information: 30
    "CBOR_TYPE_7_COUNT_30": "FE00000000000000",
    # Type 7, break (31)
    #     Header: 11111111 (Major type: 111, Additional info: 11111)
    #     Major type: 7 (simple/float/-)
    #     Additional information: 31
    "CBOR_TYPE_7_COUNT_31": "FF00000000000000",
}


@pytest.mark.parametrize(
    "test_data",
    [
        "CBOR_TAG_BROKEN_UUID",
        "CBOR_TAG_BROKEN_EPOCH_TIME",
        "CBOR_TAG_BROKEN_EPOCH_TIME_2",
        "CBOR_TAG_BROKEN_ARRAY",
        "CBOR_HUGE_ELEMENT_IN_ARRAY",
        "CBOR_UTF-8_OUT_OF_SPEC",
        "CBOR_NOT_ALLOWED_SEQUENCE",
        "CBOR_HUGE_BYTE_STRING",
        "CBOR_HUGE_UTF-8_STRING",
        "CBOR_INFINITIVE_BYTE_STRING",
        "CBOR_INCORRECTLY_ENCODED_NAN",
        "CBOR_INCORRECTLY_FORMED_DOUBLE_PRECISION_FLOAT",
        "CBOR_TYPE_7_COUNT_24",
        "CBOR_TYPE_7_COUNT_28",
        "CBOR_TYPE_7_COUNT_29",
        "CBOR_TYPE_7_COUNT_30",
    ],
)
def test_envelope_conversion_invalid_data(test_data):
    """Check if is possible to parse envelopes containing out of spec cbor data.

    suit-generator uses cbor data deserialization on multiple levels to ensure what data is encoded in the envelope.
    It is possible that deserialization will be done on data which is out of spec - for example with wrong cbor header.
    This test should check if suit-generator is able to parse properly such data.
    """
    rtemplate = Environment(loader=BaseLoader).from_string(INPUT_YAML_JINJA)
    rendered_input = rtemplate.render({"suit_manifest_component_id": CBOR_TEST_DATA[test_data]})
    test_object = yaml.load(rendered_input, Loader=yaml.Loader)
    env = SuitEnvelopeTagged.from_obj(test_object)
    cbor1 = env.to_cbor()
    env2 = SuitEnvelopeTagged.from_cbor(cbor1)
    cbor2 = env2.to_cbor()
    assert cbor1.hex() == cbor2.hex()


@pytest.mark.parametrize(
    "test_data",
    [
        "CBOR_TAG_BROKEN_UUID",
        "CBOR_TAG_BROKEN_EPOCH_TIME",
        "CBOR_TAG_BROKEN_EPOCH_TIME_2",
        "CBOR_TAG_BROKEN_ARRAY",
        "CBOR_HUGE_ELEMENT_IN_ARRAY",
        "CBOR_UTF-8_OUT_OF_SPEC",
        "CBOR_HUGE_BYTE_STRING",
        "CBOR_HUGE_UTF-8_STRING",
        "CBOR_INFINITIVE_BYTE_STRING",
        "CBOR_INCORRECTLY_ENCODED_NAN",
        "CBOR_INCORRECTLY_FORMED_DOUBLE_PRECISION_FLOAT",
        "CBOR_TYPE_7_COUNT_24",
        "CBOR_TYPE_7_COUNT_28",
        "CBOR_TYPE_7_COUNT_29",
        "CBOR_TYPE_7_COUNT_30",
    ],
)
def test_component_raw_data(test_data):
    """Check if exceptions are not raised during parsing component raw data."""
    SuitComponentIdentifierPart.from_cbor(binascii.a2b_hex(CBOR_TEST_DATA[test_data]))


def test_envelope_conversion_empty():
    """Check if ValueError is reported for missing raw suit_manifest_component_id."""
    rtemplate = Environment(loader=BaseLoader).from_string(INPUT_YAML_JINJA)
    rendered_input = rtemplate.render({"suit_manifest_component_id": ""})
    test_object = yaml.load(rendered_input, Loader=yaml.Loader)
    with pytest.raises(ValueError):
        SuitEnvelopeTagged.from_obj(test_object)


@pytest.mark.parametrize(
    "test_data",
    [
        "CBOR_TAG_BROKEN_UUID",
        "CBOR_TAG_BROKEN_EPOCH_TIME",
        "CBOR_TAG_BROKEN_EPOCH_TIME_2",
        "CBOR_TAG_BROKEN_ARRAY",
        "CBOR_HUGE_ELEMENT_IN_ARRAY",
        "CBOR_UTF-8_OUT_OF_SPEC",
        "CBOR_HUGE_BYTE_STRING",
        "CBOR_HUGE_UTF-8_STRING",
        "CBOR_INCORRECTLY_ENCODED_NAN",
        "CBOR_INCORRECTLY_ENCODED_NAN",
        "CBOR_INCORRECTLY_FORMED_DOUBLE_PRECISION_FLOAT",
        "CBOR_TYPE_7_COUNT_24",
        "CBOR_TYPE_7_COUNT_28",
        "CBOR_TYPE_7_COUNT_29",
        "CBOR_TYPE_7_COUNT_30",
    ],
)
@pytest.mark.parametrize(
    "test_object",
    [
        SuitIndex,
        SuitCommand,
        SuitSeverableCommandSequence,
        SuitSeverableText,
    ],
)
def test_object_invalid_data(test_object, test_data):
    """Check if ValueError is reported during parsing out of specification cbor data."""
    with pytest.raises(ValueError):
        test_object.from_cbor(binascii.a2b_hex(CBOR_TEST_DATA[test_data]))
