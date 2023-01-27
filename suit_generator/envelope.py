#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""SUIT envelope internal representation.

Example usage:
    - envelope creation:
        envelope = SuitEnvelope()
        envelope.load('input.yaml')
        envelope.dump('output.cbor')

    - cbor to json conversion:
        envelope = SuitEnvelope()
        envelope.load('input.suit')
        envelope.dump('output.json')
"""
from __future__ import annotations
from suit_generator.inputOutput import InputOutputMixin
import pathlib


# TODO: shall be moved into external exception module
class FileTypeException(Exception):
    """Not supported file type exception."""

    pass


class SuitEnvelope(InputOutputMixin):
    """Main SUIT envelope class."""

    def __init__(self):
        """Initialize SUIT envelope."""
        self._envelope = None

    def dump(self, file_name: str | None = None, output_type: str = "AUTO") -> None:
        """Dump internal envelope object into one of the supported file types or objects (yaml, json, cbor).

        :param file_name: input file path
        :param output_type: output file type (json, yaml, suit), type detected using extension if not provided

        """
        if output_type == "AUTO":
            # if AUTO mode used, check file extension and remove dot at the beginning
            output_type = pathlib.Path(file_name).suffix[1:]

        dump_method = self.get_serializer(output_type)
        dump_method(file_name, self._envelope)

    def load(self, file_name: str, input_type: str = "AUTO") -> None:
        """Create internal envelope object from one of the supported file types.

        :param file_name: input file path
        :param input_type: input file type (json, yaml, suit), type detected using extension if not provided

        """
        if input_type == "AUTO":
            input_type = pathlib.Path(file_name).suffix[1:]

        load_method = self.get_deserializer(input_type)
        load_method(file_name)
