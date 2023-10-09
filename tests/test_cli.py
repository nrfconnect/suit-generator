#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for cli.py implementation."""

from suit_generator.cli import main
from functools import partial
from pytest import raises


class Namespace:
    """Monkey patched namespace."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def monkey_patched_parse_arguments(cmd):
    """Monkey patched argument parser."""
    args = Namespace(output_file="test1", input_file="test2", input_format="json")
    return cmd, args


def monkey_patched_create_arguments(cmd):
    """Monkey patched argument parser."""
    args = Namespace(input_file="test1", output_format="test2", output_file="test3")
    return cmd, args


def monkey_patched_keys_arguments(cmd):
    """Monkey patched argument parser."""
    args = Namespace(output_file="test1", key_type="test2")
    return cmd, args


def monkey_patched_main_create(input_file: str, output_format: str, output_file: str):
    """Monkey patched CMD create main."""
    pass


def monkey_patched_main_keys(output_file: str, key_type: str):
    """Monkey patched CMD keys main."""
    pass


def monkey_patched_main_parse(input_file: str, output_file: str, input_format: str):
    """Monkey patched CMD parse main."""
    pass


def test_cli_create(monkeypatch):
    """Test cli create mapping."""
    # monkey patch executor and argument parser and test cli executor dictionary
    monkeypatch.setattr("suit_generator.cli.cmd_create.main.__code__", monkey_patched_main_create.__code__)
    parse_args = partial(monkey_patched_create_arguments, "create")
    monkeypatch.setattr("suit_generator.args.parse_arguments", parse_args)
    try:
        main()
    except Exception:
        assert False, "Not possible to call create command."


def test_cli_parse(monkeypatch):
    """Test cli parse mapping."""
    # monkey patch executor and argument parser and test cli executor dictionary
    monkeypatch.setattr("suit_generator.cli.cmd_create.main.__code__", monkey_patched_main_parse.__code__)
    parse_args = partial(monkey_patched_parse_arguments, "create")
    monkeypatch.setattr("suit_generator.args.parse_arguments", parse_args)
    try:
        main()
    except Exception:
        assert False, "Not possible to call parse command."


def test_cli_keys(monkeypatch):
    """Test cli keys mapping."""
    # monkey patch executor and argument parser and test cli executor dictionary
    monkeypatch.setattr("suit_generator.cli.cmd_keys.main.__code__", monkey_patched_main_keys.__code__)
    parse_args = partial(monkey_patched_keys_arguments, "keys")
    monkeypatch.setattr("suit_generator.args.parse_arguments", parse_args)
    try:
        main()
    except Exception:
        assert False, "Not possible to call keys command."


def test_cli_not_existing_cmd_mapping(monkeypatch):
    """Test cli not existing mapping."""
    # monkey patch executor and argument parser and test cli executor dictionary
    monkeypatch.setattr("suit_generator.cli.cmd_keys.main.__code__", monkey_patched_main_create.__code__)
    parse_args = partial(monkey_patched_parse_arguments, "not_existing_mapping")
    monkeypatch.setattr("suit_generator.args.parse_arguments", parse_args)
    with raises(KeyError):
        main()
