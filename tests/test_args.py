#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for args.py implementation."""

from unittest import mock
import argparse

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
