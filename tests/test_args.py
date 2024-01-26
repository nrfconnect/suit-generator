#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for args.py implementation."""

from unittest import mock
import argparse
import pytest

from suit_generator.args import parse_arguments


@mock.patch(
    "argparse.ArgumentParser.parse_args",
    return_value=argparse.Namespace(command="create", input_file="test1.json", output_file="test2.suit"),
)
def test_create_cmd_mode_auto(mock_args):
    """Test arguments parsing."""
    args = parse_arguments()
    assert args[0] == "create"
    assert vars(args[1]) == {"input_file": "test1.json", "output_file": "test2.suit"}


@pytest.mark.parametrize(
    "parameters",
    [
        ["create", "--input-file", "something.yaml", "--output-file", "something.suit"],
        ["parse", "--input-file", "something.suit", "--output-file", "something.yaml"],
        [
            "convert",
            "--input-file",
            "key.pem",
            "--output-file",
            "key.c",
            "--array-type",
            "uint8_t",
            "--array-name",
            "key_buf",
        ],
        ["image", "boot", "--input-file", "envelope.suit", "--storage-output-directory", "."],
        [
            "image",
            "update",
            "--input-file",
            "envelope.suit",
            "--storage-output-file",
            "storage.hex",
            "--dfu-partition-output-file",
            "out.hex",
        ],
        ["keys", "--output-file", "key.pem", "--type", "secp256r1", "--encoding", "pem", "--private-format", "pkcs1"],
    ],
)
def test_args_supported(parameters):
    """Ensure if application is able to parse all supported subcommands."""
    arguments = ["test_string"] + parameters
    with mock.patch("sys.argv", arguments):
        parse_arguments()


@pytest.mark.parametrize(
    "parameters",
    [
        ["create", "--input-file", "something.yaml", "--output-unsupported-argument", "something.suit"],
        ["unsupported_command", "--input-file", "something.yaml", "--output-unsupported-argument", "something.suit"],
    ],
)
def test_args_unsupported(parameters, capsys):
    """Ensure if application raises SystemExit in case of unsupported arguments."""
    arguments = ["test_string"] + parameters
    with mock.patch("sys.argv", arguments):
        with pytest.raises(SystemExit):
            parse_arguments()
        # capture output to hide argparser help in the results
        capsys.readouterr()
