# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for cmd_parse.py implementation."""
import binascii

import pytest
from unittest.mock import call

from suit_generator.cmd_parse import main as cmd_parse_main
from suit_generator.input_output import FileTypeException


SIGNED_INPUT_ENVELOPE = (
    "d86ba2025873825824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af584ad2"
    "8443a10126a0f65840e3505f7ab70bd3a0e04916f37b0d7251aa6f52ca12c7edaa886a4129a298ca6a1ecc2a57955c6b"
    "f4ccb9f01d684d5d1c4774dffbe508a034431feafa60848a2c035871a50101020003585fa202818141000458568614a4"
    "0150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45035824822f58200011223344"
    "5566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f074382030f0943821702"
)

SIGNED_OUTPUT_ENVELOPE = (
    """SUIT_Envelope_Tagged:
  suit-authentication-wrapper:
    SuitDigest:
      suit-digest-algorithm-id: cose-alg-sha-256
      suit-digest-bytes: 6658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af
    SuitAuthentication1:
      CoseSign1Tagged:
        protected:
          suit-cose-algorithm-id: cose-alg-es-256
        unprotected: {}
        payload: null\n"""
    "        signature: e3505f7ab70bd3a0e04916f37b0d7251aa6f52ca12c7edaa886a4129a298ca6a1ecc2a57955c6bf4ccb9f01d684d5d1c4774dffbe508a034431feafa60848a2c\n"  # noqa E501
    """  suit-manifest:
    suit-manifest-version: 1
    suit-manifest-sequence-number: 0
    suit-common:
      suit-components:
      - - 0
      suit-shared-sequence:
      - suit-directive-override-parameters:
          suit-parameter-vendor-identifier:
            raw: fa6b4a53d5ad5fdfbe9de663e4d41ffe
          suit-parameter-class-identifier:
            raw: 1492af1425695e48bf429b2d51f2ab45
          suit-parameter-image-digest:
            suit-digest-algorithm-id: cose-alg-sha-256
            suit-digest-bytes: 00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210
          suit-parameter-image-size:
            raw: 34768
      - suit-condition-vendor-identifier:
        - suit-send-record-success
        - suit-send-record-failure
        - suit-send-sysinfo-success
        - suit-send-sysinfo-failure
      - suit-condition-class-identifier:
        - suit-send-record-success
        - suit-send-record-failure
        - suit-send-sysinfo-success
        - suit-send-sysinfo-failure
    suit-validate:
    - suit-condition-image-match:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    suit-invoke:
    - suit-directive-invoke:
      - suit-send-record-failure
"""
)


def test_dump_to_stdout(mocker, capfd):
    """Verify if is possible to dump envelope configuration to stdout."""
    mocked_data = mocker.mock_open(read_data=binascii.a2b_hex(SIGNED_INPUT_ENVELOPE))
    mocker.patch("builtins.open", mocked_data)

    cmd_parse_main(input_file="test.suit", output_file=None, output_format="AUTO")
    out, error = capfd.readouterr()

    mocked_data().read.assert_called_once()
    assert len(out) > 0
    assert len(error) == 0
    assert out == SIGNED_OUTPUT_ENVELOPE


@pytest.mark.parametrize(
    "input_file, output_file, output_format, expected_call_content",
    [
        ("test.suit", "test.yaml", "AUTO", "SUIT_Envelope_Tagged"),  # yaml auto mode
        ("test.suit", "test.something", "yaml", "SUIT_Envelope_Tagged"),  # yaml no auto mode
        ("test.suit", "test.json", "AUTO", '"SUIT_Envelope_Tagged"'),  # json auto mode
        ("test.suit", "test.something", "json", '"SUIT_Envelope_Tagged"'),  # json auto mode
    ],
)
def test_dump(mocker, input_file, output_file, output_format, expected_call_content):
    """Verify if is possible to dump envelope to passed file format."""
    mocked_data = mocker.mock_open(read_data=binascii.a2b_hex(SIGNED_INPUT_ENVELOPE))
    mocker.patch("builtins.open", mocked_data)

    cmd_parse_main(input_file=input_file, output_file=output_file, output_format=output_format)
    mocked_data().read.assert_called_once()
    # ensure that some data has been dumped to the output file
    mocked_data().write.assert_has_calls([call(expected_call_content)])


@pytest.mark.parametrize(
    "input_file, output_file, output_format",
    [
        ("test.suit", "test.xml", "AUTO"),
        ("test.suit", "test.something", "xml"),
    ],
)
def test_dump_to_wrong_format(mocker, input_file, output_file, output_format):
    """Verify if exception is raised in case of wrong output file."""
    mocked_data = mocker.mock_open(read_data=binascii.a2b_hex(SIGNED_INPUT_ENVELOPE))
    mocker.patch("builtins.open", mocked_data)

    with pytest.raises(FileTypeException):
        cmd_parse_main(input_file=input_file, output_file=output_file, output_format=output_format)
