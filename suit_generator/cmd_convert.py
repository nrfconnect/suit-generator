#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""CONVERT_CMD CLI command entry point."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization

import os

CONVERT_CMD = "convert"


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_convert_arg_parser = parser.add_parser(
        CONVERT_CMD, help="Convert private key file in PEM format into a C file storing public key data as an array."
    )
    cmd_convert_arg_parser.add_argument("--input-file", required=True, help="Private key file in PEM format.")
    cmd_convert_arg_parser.add_argument(
        "--output-file", required=True, help="C file to be created; will hold public key data as an array."
    )
    cmd_convert_arg_parser.add_argument(
        "--array-type",
        required=False,
        default=KeyConverter.default_array_type,
        help=f"C type to be used as a key contents array. Default: {KeyConverter.default_array_type}",
    )
    cmd_convert_arg_parser.add_argument(
        "--array-name",
        required=False,
        default=KeyConverter.default_array_name,
        help=f"Valid C variable name to be used for array containing the key. "
        f"Default: {KeyConverter.default_array_name}",
    )
    cmd_convert_arg_parser.add_argument(
        "--length-type",
        required=False,
        default=KeyConverter.default_length_type,
        help=f"C type to be used as an array length variable. Default: {KeyConverter.default_length_type}",
    )
    cmd_convert_arg_parser.add_argument(
        "--length-name",
        required=False,
        default=KeyConverter.default_length_name,
        help=f"Valid C variable name to be used for array length. Default: {KeyConverter.default_length_name}",
    )
    cmd_convert_arg_parser.add_argument(
        "--columns-count",
        required=False,
        type=int,
        default=KeyConverter.default_columns_count,
        help=f"Number of columns of C code of an array. Default: {KeyConverter.default_columns_count}",
    )
    cmd_convert_arg_parser.add_argument(
        "--header-file",
        required=False,
        default=KeyConverter.default_header_file,
        help=f"Use this file's contents as a generated C file header/banner, e.g. as a license, #ifdef guards, etc. "
        f"Default: {KeyConverter.default_header_file}",
    )
    cmd_convert_arg_parser.add_argument(
        "--footer-file",
        required=False,
        default=KeyConverter.default_footer_file,
        help=f"Use this file's contents as a generated C file footer, e.g. to close #ifdef guards. "
        f"Default: {KeyConverter.default_footer_file}",
    )
    cmd_convert_arg_parser.add_argument(
        "--indentation-count",
        required=False,
        type=int,
        default=KeyConverter.default_indentation_count,
        help=f"Number of indentation characters to put at the beginning of array lines. "
        f"Default: {KeyConverter.default_indentation_count}",
    )
    cmd_convert_arg_parser.add_argument(
        "--indentation-tab",
        required=False,
        action="store_true",
        help="Use tab instead of space as indentation character.",
    )
    cmd_convert_arg_parser.add_argument(
        "--no-length", required=False, action="store_true", help="Do not create array length variable."
    )
    cmd_convert_arg_parser.add_argument(
        "--no-const", required=False, action="store_true", help="Do not use 'const' modifier for variables."
    )


class KeyConverter:
    """Creates a C file with public key data in form of an array from a private key stored in PEM format."""

    DEFAULT_ENCODING = "utf-8"

    default_array_type = "uint8_t"
    default_array_name = "key_buf"
    default_length_type = "size_t"
    default_length_name = "key_len"
    default_columns_count = 8
    default_header_file = ""
    default_footer_file = ""
    default_no_length = False
    default_no_const = False
    default_indentation_count = 4
    default_indentation_tab = False
    const_modifier = "const "
    newline = "\n"

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
        indentation_count: int = default_indentation_count,
        indentation_tab: bool = default_indentation_tab,
        no_length: bool = default_no_length,
        no_const: bool = default_no_const,
    ):
        """
        Create a C file containing an array of bytes holding data of public key.

        :param input_file: private key file in PEM format
        :param output_file: C file to be created
        :param array_type: C type to be used as a key contents array
        :param array_name: name of the array variable
        :param length_type: C type to be used for key length variable
        :param length_name: name of the key length variable
        :param columns_count: number of columns to be used for formatting the array in source code
        :param header_file: name of header file to be included at the beginning of the created C file
        :param footer_file: name of footer file to be included at the end of the created C file
        :param indentation_count: number of indentation chars to put at the beginning of a line holding the array data
        :param indentation_tab: use tab instead of space as an indentation character
        :param no_length: do not create key length variable
        :param no_const: do not use 'const' modifier for created variables
        """
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
        self._indentation_character = "\t" if indentation_tab else " "
        self._indentation_count = indentation_count
        self._indentation = self._indentation_character * self._indentation_count

        self._validate()

    def _validate(self):
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
        if self._indentation_count < 0:
            raise ValueError(f"Invalid indentation count: {self._indentation_count}")

        # Header and footer files can be empty
        # no length and no const are boolean and both values are allowed

        self._validate_input_file()

    def _validate_input_file(self):
        if os.path.exists(self._input_file):
            if os.path.getsize(self._input_file) <= 0:
                raise ValueError(f"Empty file {self._input_file}")
        else:
            raise FileNotFoundError(f"Input file {self._input_file} not found")

    def _prepare_header(self) -> str:
        if self._header_file:
            with open(self._header_file, "r", encoding=self.DEFAULT_ENCODING) as fd:
                contents = fd.read()
            if len(contents) > 0:
                contents += KeyConverter.newline * 2
            return contents
        else:
            return ""

    def _prepare_modifier(self) -> str:
        return "" if self._no_const else KeyConverter.const_modifier

    def _prepare_array_type(self) -> str:
        return f"{self._array_type} "

    def _prepare_array_variable(self) -> str:
        return f"{self._array_name}[] = {{"

    def _prepare_array_definition(self) -> str:
        return (
            self._prepare_modifier()
            + self._prepare_array_type()
            + self._prepare_array_variable()
            + KeyConverter.newline
        )

    def _prepare_array_variable_end(self) -> str:
        return "};" + KeyConverter.newline

    def _prepare_length_variable(self) -> str:
        if self._no_length:
            return ""

        right_hand_side = ""
        if self._length_type != KeyConverter.default_length_type:
            # A cast is needed
            right_hand_side = f"({self._length_type}) "
        right_hand_side += f"sizeof({self._array_name});"

        text = "" if self._no_const else KeyConverter.const_modifier
        text += f"{self._length_type} {self._length_name} = {right_hand_side}"

        # When length variable was created, surround it with newlines
        if len(text) > 0:
            text = KeyConverter.newline + text + KeyConverter.newline

        return text

    def _prepare_footer(self) -> str:
        if self._footer_file:
            with open(self._footer_file, "r", encoding=self.DEFAULT_ENCODING) as fd:
                contents = fd.read()
            if len(contents) > 0:
                contents = KeyConverter.newline + contents
            return contents
        else:
            return ""

    def _get_public_key_data(self) -> bytes:
        with open(self._input_file, "rb") as fd:
            # TODO: Consider adding support for keys protected by password
            private_key = serialization.load_pem_private_key(data=fd.read(), password=None)

        public_key_numbers = private_key.public_key().public_numbers()

        # Make sure that if bit length is not aligned to 8, full bytes will be used
        x_byte_length = (public_key_numbers.x.bit_length() + 7) // 8
        y_byte_length = (public_key_numbers.y.bit_length() + 7) // 8

        # Convert the numbers into bytes
        x_bytes = public_key_numbers.x.to_bytes(length=x_byte_length, byteorder="big")
        y_bytes = public_key_numbers.y.to_bytes(length=y_byte_length, byteorder="big")

        return x_bytes + y_bytes

    def _split_bytes_per_row(self, data: bytes) -> list[bytes]:
        return [data[i : i + self._columns_count] for i in range(0, len(data), self._columns_count)]

    def _format_row_of_bytes(self, data: bytes) -> str:
        text = ""
        for b in data:
            text += f"0x{b:02x}, "
        return text

    def _format_row(self, data: bytes) -> str:
        return self._indentation + self._format_row_of_bytes(data).strip()

    def _prepare_array(self) -> str:
        public_key_data = self._get_public_key_data()
        text = ""
        for row in self._split_bytes_per_row(public_key_data):
            text += self._format_row(row)
            text += KeyConverter.newline

        # To simplify row generation, comma and new line is always added at the end.
        # In last row, however, we don't want a trailing comma (e.g. to support C89)
        text = text[:-2]
        text += KeyConverter.newline

        return text

    def prepare_file_contents(self):
        """Prepare a C file text containing public key data stored as an array."""
        text = self._prepare_header()
        text += self._prepare_array_definition()
        text += self._prepare_array()
        text += self._prepare_array_variable_end()
        text += self._prepare_length_variable()
        text += self._prepare_footer()

        return text

    def generate_c_file(self):
        """Create a C file containing public key data stored as an array."""
        with open(self._output_file, "w", encoding=self.DEFAULT_ENCODING) as fd:
            fd.write(self.prepare_file_contents())


def main(
    input_file: str,
    output_file: str,
    array_type: str,
    array_name: str,
    length_type: str,
    length_name: str,
    columns_count: int,
    header_file: str,
    footer_file: str,
    indentation_count: int,
    indentation_tab: bool,
    no_length: bool,
    no_const: bool,
) -> None:
    """
    Create a C file containing an array of bytes holding data of public key based on provided private key in PEM format.

    :param input_file: private key file in PEM format
    :param output_file: C file to be created
    :param array_type: C type to be used as a key contents array
    :param array_name: name of the array variable
    :param length_type: C type to be used for key length variable
    :param length_name: name of the key length variable
    :param columns_count: number of columns to be used for formatting the array in source code
    :param header_file: name of header file to be included at the beginning of the created C file
    :param footer_file: name of footer file to be included at the end of the created C file
    :param indentation_count: number of indentation chars to put at the beginning of a line holding the array data
    :param indentation_tab: use tab instead of space as an indentation character
    :param no_length: do not create key length variable
    :param no_const: do not use 'const' modifier for created variables
    """
    converter = KeyConverter(
        input_file,
        output_file,
        array_type,
        array_name,
        length_type,
        length_name,
        columns_count,
        header_file,
        footer_file,
        indentation_count,
        indentation_tab,
        no_length,
        no_const,
    )
    converter.generate_c_file()
