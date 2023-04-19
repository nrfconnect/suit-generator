#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""CMD_SIGN CLI command entry point."""
import logging
from abc import ABC, abstractmethod
from suit_generator.envelope import SuitEnvelope
from suit_generator.exceptions import SUITError

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
        try:
            envelope = SuitEnvelope()
            envelope.load(input_file, "suit_simplified")
            envelope.dump(output_file, "suit_simplified", private_key=key)
        except ValueError as error:
            raise SUITError(f"Invalid value: {error}") from error
        except FileNotFoundError as error:
            raise SUITError(f"Invalid path: {error}") from error


def main(input_file: str, output_file: str, private_key: str) -> None:
    """Sign SUIT manifest.

    :param input_file: input file path
    :param output_file: output file path
    :param private_key: output file format

    """
    signer = LocalSigner()
    signer.sign(input_file, output_file, private_key)
