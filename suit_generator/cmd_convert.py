#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""CONVERT_CMD CLI command entry point."""

from __future__ import annotations


class KeyConverter:
    """Converts key files iarrays."""

    default_array_type = "uint8_t"
    default_array_name = "key_buf"
    default_length_type = "size_t"
    default_length_name = "key_len"
    default_columns_count = 8
    default_header_file = ""
    default_footer_file = ""
    default_no_length = False
    default_no_const = False

    const_modifier = "const "

    def __init__(
        self,
        input_file: str,
        output_file: str,
        array_type: str = default_array_type,
        array_name: str = default_array_name,
        length_type: str = default_length_type,
        length_name: str = default_length_name,
        columns_count: int = default_columns_count,
        header_file: str = default_header_file,
        footer_file: str = default_footer_file,
        no_length: bool = default_no_length,
        no_const: bool = default_no_const,
    ):
        self._input_file = input_file
        self._output_file = output_file
        self._array_type = array_type
        self._array_name = array_name
        self._length_type = length_type
        self._length_name = length_name
        self._columns_count = columns_count
        self._header_file = header_file
        self._footer_file = footer_file
        self._no_length = no_length
        self._no_const = no_const

        self._validate()

    # TODO: Add length type casting for non-size_t

    def _validate(self):
        if self._input_file.strip() == "":
            raise ValueError(f"Invalid input file: {self._input_file}")
        if self._output_file.strip() == "":
            raise ValueError(f"Invalid output file: {self._output_file}")
        if self._array_type.strip() == "":
            raise ValueError(f"Invalid array_type: {self._array_type}")
        if self._array_name.strip() == "":
            raise ValueError(f"Invalid array_name: {self._array_name}")
        if self._length_type.strip() == "":
            raise ValueError(f"Invalid array_length {self._length_type}")
        if self._length_name.strip() == "":
            raise ValueError(f"Invalid length_name: {self._length_name}")
        if self._columns_count <= 0:
            raise ValueError(f"Invalid columns count: {self._columns_count}")
        # Header and footer files can be empty
        # no length and no const are boolean and both values are allowed

    def _prepare_header(self) -> str:
        if self._header_file:
            with open(self._header_file, "r") as fd:
                return fd.read()
        else:
            return ""

    def _prepare_modifier(self) -> str:
        return "" if self._no_const else KeyConverter.const_modifier

    def _prepare_array_type(self) -> str:
        return f"{self._array_type} "

    def _prepare_array_variable(self) -> str:
        return f"{self._array_name}[] = {{"

    def _prepare_array_variable_end(self) -> str:
        return "};"

    def _prepare_footer(self) -> str:
        if self._footer_file:
            with open(self._footer_file, "r") as fd:
                return fd.read()
        else:
            return ""


def main(
    input_file: str,
    output_file: str,
    array_type: str,
    array_name: str,
    length_type: str,
    length_name: str,
    columns: int,
    header_file: str,
    footer_file: str,
    no_length: bool,
    no_const: bool,
) -> None:
    # TODO: Describe
    converter = KeyConverter(
        input_file,
        output_file,
        array_type,
        array_name,
        length_type,
        length_name,
        columns,
        header_file,
        footer_file,
        no_length,
        no_const,
    )
    # TODO: Do sth useful
