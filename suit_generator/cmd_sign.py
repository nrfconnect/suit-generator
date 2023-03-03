#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""CMD_SIGN CLI command entry point."""
import logging
from abc import ABC, abstractmethod

log = logging.getLogger(__name__)


class Signer(ABC):
    """Abstract class for Signers."""

    @abstractmethod
    def sign(self, input_file: str, output_file: str, key: str) -> None:
        """Sign manifest."""
        pass


class LocalSigner(Signer):
    """Implementation of local signer."""

    def sign(self, input_file: str, output_file: str, key: str) -> None:
        """Sign manifest using local files."""
        log.info(f"signing {input_file=} by {key=} and storing as {output_file=}")


def main(input_file: str, output_file: str, private_key: str) -> None:
    """Sign SUIT manifest.

    :param input_file: input file path
    :param output_file: output file path
    :param private_key: output file format

    """
    signer = LocalSigner()
    signer.sign(input_file, output_file, private_key)
