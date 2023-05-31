#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Input and output extensions for storing objects as yaml, json or cbor."""
from __future__ import annotations
from typing import Callable
from suit_generator.suit.envelope import SuitEnvelopeTagged, SuitEnvelopeTaggedSimplified
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
    }

    DESERIALIZERS = {
        "json": "from_json_file",
        "yaml": "from_yaml_file",
        "suit": "from_suit_file",
        "suit_simplified": "from_suit_file_simplified",
    }

    @classmethod
    def from_json_file(cls, file_name: str) -> dict:
        """Read json file and return dict."""
        with open(file_name, "r") as fh:
            data = json.load(fh)
        return data

    @classmethod
    def to_json_file(cls, file_name: str, data: dict, *args) -> None:
        """Write dict content into json file."""
        with open(file_name, "w") as fh:
            json.dump(data, fh, sort_keys=False)

    @classmethod
    def from_yaml_file(cls, file_name) -> dict:
        """Read yaml file and return dict."""
        with open(file_name, "r") as fh:
            data = yaml.load(fh, Loader=yaml.SafeLoader)
        return data

    @classmethod
    def to_yaml_file(cls, file_name, data, *args) -> None:
        """Write dict content into yaml file."""
        with open(file_name, "w") as fh:
            yaml.dump(data, fh, sort_keys=False)

    @classmethod
    def from_suit_file(cls, file_name) -> dict:
        """Read suit file and return dict."""
        with open(file_name, "rb") as fh:
            data = fh.read()
            suit = SuitEnvelopeTagged.from_cbor(data)
            return suit.to_obj()

    @classmethod
    def from_suit_file_simplified(cls, file_name) -> dict:
        """Read suit file and return dict."""
        with open(file_name, "rb") as fh:
            data = fh.read()
            suit = SuitEnvelopeTaggedSimplified.from_cbor(data)
            return suit.to_obj()

    def prepare_suit_data(self, data, private_key=None) -> bytes:
        """Convert data to suit format."""
        suit_obj = SuitEnvelopeTagged.from_obj(data)
        suit_obj.update_severable_digests()
        suit_obj.update_digest()
        if private_key:
            with open(private_key, "rb") as pk_fh:
                pk_data = pk_fh.read()
            suit_obj.sign(pk_data)
        return suit_obj.to_cbor()

    def to_suit_file(self, file_name, data, private_key=None) -> None:
        """Write dict content into suit file."""
        with open(file_name, "wb") as fh:
            fh.write(self.prepare_suit_data(data, private_key))

    def to_suit_file_simplified(self, file_name, data, private_key=None) -> None:
        """Write dict content into suit file."""
        with open(file_name, "wb") as fh:
            suit_obj = SuitEnvelopeTaggedSimplified.from_obj(data)
            suit_obj.update_digest()
            if private_key:
                with open(private_key, "rb") as pk_fh:
                    pk_data = pk_fh.read()
                suit_obj.sign(pk_data)
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
