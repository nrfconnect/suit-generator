#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""SUIT envelope internal representation."""
from __future__ import annotations
from suit_generator.input_output import InputOutputMixin
from suit_generator.envelope_api import EnvelopeApiMixin
import pathlib


# TODO: shall be moved into external exception module
class FileTypeException(Exception):
    """Not supported file type exception."""

    pass


class SuitEnvelope(InputOutputMixin, EnvelopeApiMixin):
    """Main SUIT envelope class."""

    def __init__(self):
        """Initialize SUIT envelope."""
        self._envelope = None

    def dump(
        self,
        file_name: str | None = None,
        output_type: str = "AUTO",
        parse_hierarchy: bool = False,
    ) -> None:
        """Dump internal envelope object into one of the supported file types or objects (yaml, json, cbor).

        :param file_name: input file path
        :param output_type: output file type (json, yaml, suit), type detected using extension if not provided
        :param parse_hierarchy: parse sub-manifests (True/False)

        """
        if output_type == "AUTO" and file_name is not None:
            # if AUTO mode used, check file extension and remove dot at the beginning
            output_type = pathlib.Path(file_name).suffix[1:]

        if file_name is None:
            output_type = "STDOUT"

        dump_method = self.get_serializer(output_type)
        dump_method(file_name, self._envelope, parse_hierarchy)

    def load(self, file_name: str, input_type: str = "AUTO") -> None:
        """Create internal envelope object from one of the supported file types.

        :param file_name: input file path
        :param input_type: input file type (json, yaml, suit), type detected using extension if not provided

        """
        if input_type == "AUTO":
            input_type = pathlib.Path(file_name).suffix[1:]

        load_method = self.get_deserializer(input_type)
        self._envelope = load_method(file_name)

    def sever(self) -> None:
        """Get rid of severable elements."""
        severable = [
            "suit-payload-fetch",
            "suit-install",
            "suit-dependency-resolution",
            "suit-candidate-verification",
            "suit-text",
            "suit-integrated-payloads",
            "suit-integrated-dependencies",
        ]
        [
            self._envelope["SUIT_Envelope_Tagged"].pop(k, None)
            for k in list(self._envelope["SUIT_Envelope_Tagged"].keys())
            if k in severable
        ]
