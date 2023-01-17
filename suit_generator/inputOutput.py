#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Input and output extensions for storing objects as yaml, json or cbor."""
from __future__ import annotations
import json
import yaml


class InputOutputMixin:
    """Input and output extensions."""

    @classmethod
    def from_json_file(cls, file_name: str) -> dict:
        """Read json file and return dict."""
        with open(file_name, "r") as fh:
            data = json.load(fh)
        return data

    @classmethod
    def to_json_file(cls, file_name: str, data: dict) -> None:
        """Write dict content into json file."""
        with open(file_name, "w") as fh:
            json.dump(data, fh)

    @classmethod
    def from_yaml_file(cls, file_name):
        """Read yaml file and return dict."""
        with open(file_name, "r") as fh:
            data = yaml.load(fh)
        return data

    @classmethod
    def to_yaml_file(cls, file_name, data):
        """Write dict content into yaml file."""
        with open(file_name, "w") as fh:
            yaml.dump(data, fh)
