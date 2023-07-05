#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Example implementation of envelope signing."""

import sys
import pathlib
from argparse import ArgumentParser

sys.path.append(str(pathlib.Path(__file__).parents[1].absolute()))

if True:  # noqa: E402
    from suit_generator.cmd_sign import LocalSigner

PRIVATE_KEY = pathlib.Path(__file__).parent / "key_private.pem"

parser = ArgumentParser()
parser.add_argument("--input-file", required=True, help="Input envelope.")
parser.add_argument("--output-file", required=True, help="Output envelope.")

arguments = parser.parse_args()

signer = LocalSigner()
signer.sign(arguments.input_file, arguments.output_file, PRIVATE_KEY)