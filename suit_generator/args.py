#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

"""Implementation of CLI argument parser."""

from argparse import ArgumentParser
from typing import Tuple

from suit_generator.cmd_create import add_arguments as create_args
from suit_generator.cmd_parse import add_arguments as parse_args
from suit_generator.cmd_keys import add_arguments as key_args
from suit_generator.cmd_image import add_arguments as image_args
from suit_generator.cmd_convert import add_arguments as convert_args
from suit_generator.cmd_mpi import add_arguments as mpi_args


def _parser() -> ArgumentParser:
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True, help="Choose subcommand:")
    create_args(subparsers)
    parse_args(subparsers)
    key_args(subparsers)
    image_args(subparsers)
    convert_args(subparsers)
    mpi_args(subparsers)
    return parser


def parse_arguments() -> Tuple:
    """
    Parse CLI parameters.

    Parse passed CLI parameters and return argparse.Namespace

    :return: Tuple contains command and it's parameters
    """
    parser = _parser()
    arguments = parser.parse_args()
    cmd = str(arguments.command)

    # remove unnecessary arguments to simplify command calling
    del arguments.command

    return cmd, arguments
