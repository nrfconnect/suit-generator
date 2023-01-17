#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
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
    args = Namespace(arg1="test1", arg2="test2")
    return cmd, args


def monkey_patched_main(*args, **kwargs):
    """Monkey patched CMD main."""
    pass


def test_cli_create(monkeypatch):
    """Test cli create mapping."""
    # monkey patch executor and argument parser and test cli executor dictionary
    monkeypatch.setattr("suit_generator.cli.cmd_create.main.__code__", monkey_patched_main.__code__)
    parse_args = partial(monkey_patched_parse_arguments, "create")
    monkeypatch.setattr("suit_generator.args.parse_arguments", parse_args)
    try:
        main()
    except Exception:
        assert False, "Not possible to call create command."


def test_cli_parse(monkeypatch):
    """Test cli parse mapping."""
    # monkey patch executor and argument parser and test cli executor dictionary
    monkeypatch.setattr("suit_generator.cli.cmd_create.main.__code__", monkey_patched_main.__code__)
    parse_args = partial(monkey_patched_parse_arguments, "create")
    monkeypatch.setattr("suit_generator.args.parse_arguments", parse_args)
    try:
        main()
    except Exception:
        assert False, "Not possible to call parse command."


def test_cli_keys(monkeypatch):
    """Test cli keys mapping."""
    # monkey patch executor and argument parser and test cli executor dictionary
    monkeypatch.setattr("suit_generator.cli.cmd_keys.main.__code__", monkey_patched_main.__code__)
    parse_args = partial(monkey_patched_parse_arguments, "keys")
    monkeypatch.setattr("suit_generator.args.parse_arguments", parse_args)
    try:
        main()
    except Exception:
        assert False, "Not possible to call keys command."


def test_cli_sign(monkeypatch):
    """Test cli sign mapping."""
    # monkey patch executor and argument parser and test cli executor dictionary
    monkeypatch.setattr("suit_generator.cli.cmd_sign.main.__code__", monkey_patched_main.__code__)
    parse_args = partial(monkey_patched_parse_arguments, "sign")
    monkeypatch.setattr("suit_generator.args.parse_arguments", parse_args)
    try:
        main()
    except Exception:
        assert False, "Not possible to call sign command."


def test_cli_not_existing_cmd_mapping(monkeypatch):
    """Test cli not existing mapping."""
    # monkey patch executor and argument parser and test cli executor dictionary
    monkeypatch.setattr("suit_generator.cli.cmd_keys.main.__code__", monkey_patched_main.__code__)
    parse_args = partial(monkey_patched_parse_arguments, "not_existing_mapping")
    monkeypatch.setattr("suit_generator.args.parse_arguments", parse_args)
    with raises(KeyError):
        main()
