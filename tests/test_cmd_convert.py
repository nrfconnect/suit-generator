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

PRIVATE_KEY_FILE_NONEMPTY = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCCbgTEad8JOIU8sg
IJUKm7Lle0358XoaxNfbs4nqd4WhRANCAATt0J6l7OTtvmwI50cJVZo4KcUxMyJ7
9PARbowFLQIODsPg2Df0wm/BKIAvRTgaIytt1dooYABdq+Kgg9vvOFUT
-----END PRIVATE KEY-----
"""

EXPECTED_PRIVATE_KEY_BYTES = (
    b"\xed\xd0\x9e\xa5\xec\xe4\xed\xbel\x08\xe7G\tU\x9a"
    b'8)\xc513"{\xf4\xf0\x11n\x8c\x05-\x02\x0e\x0e\xc3\xe0\xd87\xf4\xc2o\xc1(\x80'
    b"/E8\x1a#+m\xd5\xda(`\x00]\xab\xe2\xa0\x83\xdb\xef8U\x13"
)

EXPECTED_GENERATED_FILE_ORIGINAL = """const uint8_t public_key[] = {
    0xed, 0xd0, 0x9e, 0xa5, 0xec, 0xe4, 0xed, 0xbe, 0x6c, 0x08, 0xe7, 0x47,
    0x09, 0x55, 0x9a, 0x38, 0x29, 0xc5, 0x31, 0x33, 0x22, 0x7b, 0xf4, 0xf0,
    0x11, 0x6e, 0x8c, 0x05, 0x2d, 0x02, 0x0e, 0x0e, 0xc3, 0xe0, 0xd8, 0x37,
    0xf4, 0xc2, 0x6f, 0xc1, 0x28, 0x80, 0x2f, 0x45, 0x38, 0x1a, 0x23, 0x2b,
    0x6d, 0xd5, 0xda, 0x28, 0x60, 0x00, 0x5d, 0xab, 0xe2, 0xa0, 0x83, 0xdb,
    0xef, 0x38, 0x55, 0x13
};
"""


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
def mocker_private_key_file_nonempty(mocker):
    mocked_data = mocker.mock_open(read_data=PRIVATE_KEY_FILE_NONEMPTY)
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


def test_get_public_key_data_nonempty(mocker_private_key_file_nonempty):
    # GIVEN a converter
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file")
    # WHEN input file's data is used to request public key data
    public_key_data = converter._get_public_key_data()
    # THEN it is as expected
    assert public_key_data == EXPECTED_PRIVATE_KEY_BYTES


def test_array_definition_default(default_converter):
    # GIVEN default converter
    # WHEN array definition is created
    definition = default_converter._prepare_array_definition()
    # THEN it is as expected
    assert definition == "const uint8_t key_buf[] = {"


def test_array_definition_no_const():
    # GIVEN a converter with "--no-const"
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", no_const=True)
    # WHEN array definition is created
    definition = converter._prepare_array_definition()
    # THEN it is as expected
    assert definition == "uint8_t key_buf[] = {"


def test_array_definition_custom_type():
    # GIVEN a converter with "char" used as a array type
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", array_type="char")
    # WHEN array definition is created
    definition = converter._prepare_array_definition()
    # THEN it is as expected
    assert definition == "const char key_buf[] = {"


def test_array_definition_custom_name():
    # GIVEN a converter with custom array name
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", array_name="foo")
    # WHEN array definition is created
    definition = converter._prepare_array_definition()
    # THEN it is as expected
    assert definition == "const uint8_t foo[] = {"


def test_length_definition_default(default_converter):
    # GIVEN default converter
    # WHEN length variable definition is prepared
    text = default_converter._prepare_length_variable()
    # THEN it is as following
    assert text == "const size_t key_len = sizeof(key_buf);"


def test_length_definition_no_const():
    # GIVEN converter with "--no-const"
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", no_const=True)
    # WHEN length variable definition is prepared
    text = converter._prepare_length_variable()
    # THEN it is as following
    assert text == "size_t key_len = sizeof(key_buf);"


def test_length_definition_custom_type():
    # GIVEN converter with custom length type
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", length_type="uint32_t")
    # WHEN length variable definition is prepared
    text = converter._prepare_length_variable()
    # THEN it is as following
    assert text == "const uint32_t key_len = (uint32_t) sizeof(key_buf);"


def test_length_definition_custom_name():
    # GIVEN converter with custom length name
    converter = KeyConverter(
        input_file="some_input_file", output_file="some_output_file", length_name="my_fancy_length_name"
    )
    # WHEN length variable definition is prepared
    text = converter._prepare_length_variable()
    # THEN it is as following
    assert text == "const size_t my_fancy_length_name = sizeof(key_buf);"


def test_length_definition_no_length():
    # GIVEN converter with no length variable desired
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", no_length=True)
    # WHEN length variable definition is prepared
    text = converter._prepare_length_variable()
    # THEN it is empty
    assert text == ""


def test_file_contents(mocker_private_key_file_nonempty):
    # GIVEN converter with particular configuration
    converter = KeyConverter(
        input_file="some_input_file",
        output_file="some_output_file",
        array_name="public_key",
        no_length=True,
        columns_count=12,
    )
    # WHEN file contents are generated
    contents = converter._prepare_file_contents()
    # THEN they match original content generated using suit-tool
    assert contents == EXPECTED_GENERATED_FILE_ORIGINAL


def test_file_creation_original(tmpdir):
    # GIVEN converter with particular configuration
    out_file = tmpdir.join("some_output_file")
    print(out_file)
    converter = KeyConverter(
        # TODO: Find a way to not depend on existence of real key file...
        input_file="key_private.pem",
        output_file=out_file.strpath,
        array_name="public_key",
        no_length=True,
        columns_count=12,
    )
    # WHEN C file is created
    converter.generate_c_file()

    # THEN its contents match the ones generated using suit-tool
    with open(out_file.strpath, "r") as fd:
        generated = fd.read()
    assert generated == EXPECTED_GENERATED_FILE_ORIGINAL
