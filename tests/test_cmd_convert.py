#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for cmd_convert.py implementation."""

import pytest

from suit_generator.cmd_convert import KeyConverter

HEADER_FILE_DATA_NON_EMPTY = "#ifdef USE_HEADER__"
FOOTER_FILE_DATA_NON_EMPTY = "#endif /* USE_HEADER__ */"

INPUT_FILE_DATA_LOREM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

EXPECTED_LOREM_1 = [
    "L",
    "o",
    "r",
    "e",
    "m",
    " ",
    "i",
    "p",
    "s",
    "u",
    "m",
    " ",
    "d",
    "o",
    "l",
    "o",
    "r",
    " ",
    "s",
    "i",
    "t",
    " ",
    "a",
    "m",
    "e",
    "t",
    ",",
    " ",
    "c",
    "o",
    "n",
    "s",
    "e",
    "c",
    "t",
    "e",
    "t",
    "u",
    "r",
    " ",
    "a",
    "d",
    "i",
    "p",
    "i",
    "s",
    "c",
    "i",
    "n",
    "g",
    " ",
    "e",
    "l",
    "i",
    "t",
    ",",
    " ",
    "s",
    "e",
    "d",
    " ",
    "d",
    "o",
    " ",
    "e",
    "i",
    "u",
    "s",
    "m",
    "o",
    "d",
    " ",
    "t",
    "e",
    "m",
    "p",
    "o",
    "r",
    " ",
    "i",
    "n",
    "c",
    "i",
    "d",
    "i",
    "d",
    "u",
    "n",
    "t",
    " ",
    "u",
    "t",
    " ",
    "l",
    "a",
    "b",
    "o",
    "r",
    "e",
    " ",
    "e",
    "t",
    " ",
    "d",
    "o",
    "l",
    "o",
    "r",
    "e",
    " ",
    "m",
    "a",
    "g",
    "n",
    "a",
    " ",
    "a",
    "l",
    "i",
    "q",
    "u",
    "a",
    ".",
]
EXPECTED_LOREM_2 = [
    "Lo",
    "re",
    "m ",
    "ip",
    "su",
    "m ",
    "do",
    "lo",
    "r ",
    "si",
    "t ",
    "am",
    "et",
    ", ",
    "co",
    "ns",
    "ec",
    "te",
    "tu",
    "r ",
    "ad",
    "ip",
    "is",
    "ci",
    "ng",
    " e",
    "li",
    "t,",
    " s",
    "ed",
    " d",
    "o ",
    "ei",
    "us",
    "mo",
    "d ",
    "te",
    "mp",
    "or",
    " i",
    "nc",
    "id",
    "id",
    "un",
    "t ",
    "ut",
    " l",
    "ab",
    "or",
    "e ",
    "et",
    " d",
    "ol",
    "or",
    "e ",
    "ma",
    "gn",
    "a ",
    "al",
    "iq",
    "ua",
    ".",
]
EXPECTED_LOREM_8 = [
    "Lorem ip",
    "sum dolo",
    "r sit am",
    "et, cons",
    "ectetur ",
    "adipisci",
    "ng elit,",
    " sed do ",
    "eiusmod ",
    "tempor i",
    "ncididun",
    "t ut lab",
    "ore et d",
    "olore ma",
    "gna aliq",
    "ua.",
]
EXPECTED_LOREM_32 = [
    "Lorem ipsum dolor sit amet, cons",
    "ectetur adipiscing elit, sed do ",
    "eiusmod tempor incididunt ut lab",
    "ore et dolore magna aliqua.",
]


@pytest.fixture
def default_converter():
    """Converted created only with mandatory arguments, leaving other set to default ones"""
    return KeyConverter(
        input_file="some_input_file",
        output_file="some_output_file",
    )


@pytest.fixture
def valid_converter():
    return KeyConverter(
        input_file="some_input_file",
        output_file="some_output_file",
        array_type="uint8_t",
        array_name="key_buf",
        length_type="size_t",
        length_name="key_len",
        columns_count=8,
        header_file="some_header_file",
        footer_file="some_footer_file",
        no_length=False,
        no_const=False,
    )


@pytest.fixture
def mocker_empty_file(mocker):
    mocked_data = mocker.mock_open(read_data="")
    mocker.patch("builtins.open", mocked_data)


# TODO: Maybe this mockers can be reused and data to be read could be passed?
@pytest.fixture
def mocker_header_file_nonempty(mocker):
    mocked_data = mocker.mock_open(read_data=HEADER_FILE_DATA_NON_EMPTY)
    mocker.patch("builtins.open", mocked_data)


@pytest.fixture
def mocker_footer_file_nonempty(mocker):
    mocked_data = mocker.mock_open(read_data=FOOTER_FILE_DATA_NON_EMPTY)
    mocker.patch("builtins.open", mocked_data)


@pytest.fixture
def mocker_input_file_lorem(mocker):
    mocked_data = mocker.mock_open(read_data=INPUT_FILE_DATA_LOREM)
    mocker.patch("builtins.open", mocked_data)


def test_validate_invalid_input_file():
    # GIVEN empty input file name
    # WHEN converter is created
    # THEN it raises an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="", output_file="some_output_file")


def test_validate_invalid_output_file():
    # GIVEN empty output file name
    # WHEN converter is created
    # THEN it raises an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="")


def test_validate_array_type():
    # GIVEN empty array variable type
    # WHEN converter is created
    # THEN it rases an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", array_type="")


def test_validate_array_name():
    # GIVEN empty array variable name
    # WHEN converter is created
    # THEN it rases an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", array_name="")


def test_validate_length_type():
    # GIVEN empty length variable type
    # WHEN converter is created
    # THEN it rases an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", length_type="")


def test_validate_length_name():
    # GIVEN empty length variable name
    # WHEN converter is created
    # THEN it rases an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", length_name="")


def test_validate_columns_count_zero():
    # GIVEN columns count set to zero
    # WHEN converter is created
    # THEN it rases an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", columns_count=0)


def test_validate_columns_count_negative():
    # GIVEN columns count set to negative value
    # WHEN converter is created
    # THEN it rases an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", columns_count=-123)


def test_prepare_header_no_header_file(default_converter):
    # GIVEN converter that has no header file name given
    # WHEN header text is prepared
    text = default_converter._prepare_header()
    # THEN it contains empty string
    assert text == ""


def test_prepare_header_empty_header(valid_converter, mocker_empty_file):
    # GIVEN converter that was given an empty header file
    # WHEN header text is prepared
    text = valid_converter._prepare_header()
    # THEN it contains empty string
    assert text == ""


def test_prepare_header_valid_header_file(valid_converter, mocker_header_file_nonempty):
    # GIVEN converter that was given valid header file
    # WHEN header text is prepared
    text = valid_converter._prepare_header()
    # THEN it contains the text file contents
    assert text == HEADER_FILE_DATA_NON_EMPTY


def test_prepare_footer_no_footer_file(default_converter):
    # GIVEN converter that has no footer file name given
    # WHEN footer text is prepared
    text = default_converter._prepare_footer()
    # THEN it contains empty string
    assert text == ""


def test_prepare_footer_empty_footer(valid_converter, mocker_empty_file):
    # GIVEN converter that was given an empty footer file
    # WHEN footer text is prepared
    text = valid_converter._prepare_footer()
    # THEN it contains empty string
    assert text == ""


def test_prepare_footer_valid_footer_file(valid_converter, mocker_footer_file_nonempty):
    # GIVEN converter that was given valid footer file
    # WHEN footer text is prepared
    text = valid_converter._prepare_footer()
    # THEN it contains the text file contents
    assert text == FOOTER_FILE_DATA_NON_EMPTY


def test_modified_use_const(default_converter):
    # GIVEN converter that had no '--no-const' argument passed
    # WHEN modifier text is prepared
    text = default_converter._prepare_modifier()
    # THEN it contains the 'const' modifier
    assert text == "const "


def test_modifier_no_const():
    # GIVEN converter that had '--no-const' argument passed
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", no_const=True)
    # WHEN modifier text is prepared
    text = converter._prepare_modifier()
    # THEN it contains empty string
    assert text == ""


def test_array_type_default(default_converter):
    # GIVEN converter with default array type
    # WHEN  array type text is prepared
    text = default_converter._prepare_array_type()
    # THEN it contains uint8_t followed by a space
    assert text == "uint8_t "


def test_array_type_custom():
    # GIVEN converter with custom array type
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", array_type="my_fancy_type_t")
    # WHEN array type text is prepared
    text = converter._prepare_array_type()
    # THEN it contains custom type name followed by a space
    assert text == "my_fancy_type_t "


def test_array_variable_default(default_converter):
    # GIVEN converter with default array name
    # WHEN array variable text is prepared
    text = default_converter._prepare_array_variable()
    # THEN it contains "key_buf[] = {"
    assert text == "key_buf[] = {"


def test_array_variable_custom():
    # GIVEN converter with custom array name
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", array_name="stuff")
    # WHEN array variable text is prepared
    text = converter._prepare_array_variable()
    # THEN it contains the custom name followed by array definition characters
    assert text == "stuff[] = {"


def test_array_variable_end(default_converter):
    # GIVEN a converter
    # WHEN an array ending characters text is prepared
    text = default_converter._prepare_array_variable_end()
    # THEN it contains "};"
    assert text == "};"


def test_read_chunks_empty_input_file(mocker_empty_file):
    # GIVEN converter with empty input file
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file")
    # WHEN input file is read by chunks
    actual = [chunk for chunk in converter._read_input_file_chunk()]

    # THEN no data is returned
    assert len(actual) == 0


# TODO: Add some parametrization for different input data...
def test_read_chunk_default_column_count(mocker_input_file_lorem):
    # GIVEN converter with non-empty input file
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file")
    # WHEN input file is read by chunks of bytes equal to default number of columns
    actual = [chunk for chunk in converter._read_input_file_chunk()]

    expected = EXPECTED_LOREM_8
    # THEN number of chunks is as expected...
    assert len(actual) == len(expected)
    # ... and all chunks are as expected
    assert all([a == b for a, b in zip(actual, expected)])


def test_read_chunk_columns_count_1(mocker_input_file_lorem):
    # GIVEN converter with non-empty input file
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", columns_count=1)
    # WHEN input file is read by chunks of single byte
    actual = [chunk for chunk in converter._read_input_file_chunk()]

    expected = EXPECTED_LOREM_1
    # THEN number of chunks is as expected...
    assert len(actual) == len(expected)
    # ... and all chunks are as expected
    assert all([a == b for a, b in zip(actual, expected)])


def test_read_chunk_columns_count_2(mocker_input_file_lorem):
    # GIVEN converter with non-empty input file
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", columns_count=2)
    # WHEN input file is read by chunks of two bytes
    actual = [chunk for chunk in converter._read_input_file_chunk()]

    expected = EXPECTED_LOREM_2
    # THEN number of chunks is as expected...
    assert len(actual) == len(expected)
    # ... and all chunks are as expected
    assert all([a == b for a, b in zip(actual, expected)])


def test_read_chunk_columns_count_32(mocker_input_file_lorem):
    # GIVEN converter with non-empty input file
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", columns_count=32)
    # WHEN input file is read by chunks of 32 bytes
    actual = [chunk for chunk in converter._read_input_file_chunk()]

    expected = EXPECTED_LOREM_32
    # THEN number of chunks is as expected...
    assert len(actual) == len(expected)
    # ... and all chunks are as expected
    assert all([a == b for a, b in zip(actual, expected)])
