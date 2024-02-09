#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Input and output extensions for storing objects as yaml, json or cbor."""
from __future__ import annotations

import binascii
from typing import Callable

from suit_generator.suit.envelope import SuitEnvelopeTagged, SuitEnvelopeTaggedSimplified
from suit_generator.suit.types.keys import suit_integrated_dependencies
import json
import yaml


# TODO: shall be moved into external exception module
class FileTypeException(Exception):
    """Not supported file type exception."""

    pass


class InputOutputMixin:
    """Input and output extensions."""

    SERIALIZERS = {
        "json": "to_json_file",
        "yaml": "to_yaml_file",
        "suit": "to_suit_file",
        "suit_simplified": "to_suit_file_simplified",
        "stdout": "to_stdout",
    }

    DESERIALIZERS = {
        "json": "from_json_file",
        "yaml": "from_yaml_file",
        "suit": "from_suit_file",
        "suit_simplified": "from_suit_file_simplified",
    }

    DEFAULT_ENCODING = "utf-8"

    @classmethod
    def from_json_file(cls, file_name: str) -> dict:
        """Read json file and return dict."""
        with open(file_name, "r", encoding=cls.DEFAULT_ENCODING) as fh:
            data = json.load(fh)
        return data

    @classmethod
    def parse_json_submanifests(cls, data: dict) -> dict:
        """Parse sub-manifests."""
        if suit_integrated_dependencies.name in data["SUIT_Envelope_Tagged"]:
            for key in data["SUIT_Envelope_Tagged"][suit_integrated_dependencies.name]:
                # create anchor in the root manifest
                data["SUIT_Envelope_Tagged"][suit_integrated_dependencies.name][key] = SuitEnvelopeTagged.from_cbor(
                    binascii.a2b_hex(data["SUIT_Envelope_Tagged"][suit_integrated_dependencies.name][key])
                ).to_obj()
        return data

    @classmethod
    def to_json_file(cls, file_name: str, data: dict, parse_hierarchy: bool, *args) -> None:
        """Write dict content into json file."""
        with open(file_name, "w", encoding=cls.DEFAULT_ENCODING) as fh:
            json.dump(cls.parse_json_submanifests(data) if parse_hierarchy is True else data, fh, sort_keys=False)

    @classmethod
    def from_yaml_file(cls, file_name: str) -> dict:
        """Read yaml file and return dict."""
        with open(file_name, "r", encoding=cls.DEFAULT_ENCODING) as fh:
            data = yaml.load(fh, Loader=yaml.SafeLoader)
        return data

    @classmethod
    def parse_yaml_submanifests(cls, data: dict) -> dict:
        """Parse sub-manifest and store as yaml anchors."""
        if suit_integrated_dependencies.name in data["SUIT_Envelope_Tagged"]:
            if "SUIT_Dependent_Manifests" not in data:
                # SUIT_Dependent_Manifest need to be created first to be dumped first and to be used as anchors source
                data = {**{"SUIT_Dependent_Manifests": {}}, **data}
            for key in data["SUIT_Envelope_Tagged"][suit_integrated_dependencies.name]:
                # create new entry in the SUIT_Dependent_Manifest
                data["SUIT_Dependent_Manifests"][f"{key}_envelope"] = cls.parse_yaml_submanifests(
                    SuitEnvelopeTagged.from_cbor(
                        binascii.a2b_hex(data["SUIT_Envelope_Tagged"][suit_integrated_dependencies.name][key])
                    ).to_obj()
                )
                # create anchor in the root manifest
                data["SUIT_Envelope_Tagged"][suit_integrated_dependencies.name][key] = data["SUIT_Dependent_Manifests"][
                    f"{key}_envelope"
                ]
        return data

    @classmethod
    def to_yaml_file(cls, file_name: str, data: dict, parse_hierarchy: bool, *args) -> None:
        """Write dict content into yaml file."""
        with open(file_name, "w", encoding=cls.DEFAULT_ENCODING) as fh:
            yaml.dump(cls.parse_yaml_submanifests(data) if parse_hierarchy is True else data, fh, sort_keys=False)

    @classmethod
    def to_stdout(cls, file_name: str, data: dict, parse_hierarchy: bool, *args) -> None:
        """Dump as yaml into STDOUT."""
        print(
            yaml.dump(cls.parse_yaml_submanifests(data) if parse_hierarchy is True else data, sort_keys=False), end=""
        )

    @classmethod
    def from_suit_file(cls, file_name: str) -> dict:
        """Read suit file and return dict."""
        with open(file_name, "rb") as fh:
            data = fh.read()
            suit = SuitEnvelopeTagged.from_cbor(data)
            return suit.to_obj()

    @classmethod
    def from_suit_file_simplified(cls, file_name: str) -> dict:
        """Read suit file and return dict."""
        with open(file_name, "rb") as fh:
            data = fh.read()
            suit = SuitEnvelopeTaggedSimplified.from_cbor(data)
            return suit.to_obj()

    @staticmethod
    def prepare_suit_data(data: dict) -> bytes:
        """Convert data to suit format."""
        suit_obj = SuitEnvelopeTagged.from_obj(data)
        suit_obj.update_severable_digests()
        suit_obj.update_digest()
        return suit_obj.to_cbor()

    def to_suit_file(self, file_name: str, data: dict, parse_hierarchy: bool) -> None:
        """Write dict content into suit file."""
        with open(file_name, "wb") as fh:
            fh.write(self.prepare_suit_data(data))

    def to_suit_file_simplified(self, file_name: str, data: dict, parse_hierarchy: bool) -> None:
        """Write dict content into suit file."""
        with open(file_name, "wb") as fh:
            suit_obj = SuitEnvelopeTaggedSimplified.from_obj(data)
            suit_obj.update_digest()
            fh.write(suit_obj.to_cbor())

    def get_serializer(self, output_type: str) -> Callable:
        """Return serialize method."""
        if output_type.lower() not in self.SERIALIZERS:
            raise FileTypeException(f"{output_type} is not supported.")
        else:
            return getattr(self, self.SERIALIZERS[output_type.lower()])

    def get_deserializer(self, input_type: str) -> Callable:
        """Return deserialize method."""
        if input_type.lower() not in self.DESERIALIZERS:
            raise FileTypeException(f"{input_type} is not supported.")
        else:
            return getattr(self, self.DESERIALIZERS[input_type.lower()])
