#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""CONVERT_CMD CLI command entry point."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization


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

        # TODO: Make it customizable
        self._indentation_character = " "
        self._indentation_count = 4
        self._indentation = self._indentation_character * self._indentation_count

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

        # self._validate_input_file()

    # TODO: Might be used if there is elegant way to mock it in tests...
    # def _validate_input_file(self):
    #     if os.path.getsize(self._input_file) <= 0:
    #         raise ValueError(f"Empty file {self._input_file}")

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

    def _prepare_array_definition(self) -> str:
        return self._prepare_modifier() + self._prepare_array_type() + self._prepare_array_variable()

    def _prepare_array_variable_end(self) -> str:
        return "};"

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

        return text

    def _prepare_footer(self) -> str:
        if self._footer_file:
            with open(self._footer_file, "r") as fd:
                return fd.read()
        else:
            return ""

    def _get_public_key_data(self) -> bytes:
        with open(self._input_file, "rb") as fd:
            # TODO: What if the key is protected by a password?
            private_key = serialization.load_pem_private_key(data=fd.read(), password=None)

        public_key_numbers = private_key.public_key().public_numbers()

        # Make sure that if bit length is not alligned to 8, full bytes will be used
        x_bit_length = (public_key_numbers.x.bit_length() + 7) // 8
        y_bit_length = (public_key_numbers.y.bit_length() + 7) // 8

        # Convert the numbers into bytes
        x_bytes = public_key_numbers.x.to_bytes(length=x_bit_length, byteorder="big")
        y_bytes = public_key_numbers.y.to_bytes(length=y_bit_length, byteorder="big")

        return x_bytes + y_bytes

    def _split_bytes_per_row(self, data: bytes):
        # TODO: Add return type annotation
        return [data[i : i + self._columns_count] for i in range(0, len(data), self._columns_count)]

    def _format_row_of_bytes(self, data: bytes):
        # TODO: Add return type annotation
        text = ""
        for b in data:
            text += f"0x{b:02x}, "
        return text

    def _format_row(self, data: bytes):
        # TODO: Add return type annotation
        return self._indentation + self._format_row_of_bytes(data).strip()

    def _prepare_file_contents(self):
        text = ""

        header_text = self._prepare_header()
        if len(header_text) > 0:
            text += header_text
            text += KeyConverter.newline

        text += self._prepare_array_definition()
        text += KeyConverter.newline

        public_key_data = self._get_public_key_data()
        array_text = ""
        for row in self._split_bytes_per_row(public_key_data):
            array_text += self._format_row(row)
            array_text += KeyConverter.newline

        # To simplify row generation, comma and new line is always added at the end.
        # In last row, however, we don't want a trailing comma (e.g. to support C89)
        array_text = array_text[:-2]
        array_text += KeyConverter.newline

        text += array_text

        text += self._prepare_array_variable_end()
        text += KeyConverter.newline

        length_variable = self._prepare_length_variable()
        if len(length_variable) > 0:
            text += KeyConverter.newline
            text += length_variable
            text += KeyConverter.newline

        return text

    def generate_c_file(self):
        with open(self._output_file, "w") as fd:
            fd.write(self._prepare_file_contents())


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
        columns_count,
        header_file,
        footer_file,
        no_length,
        no_const,
    )
    # TODO: Do sth useful
    converter.sth()
