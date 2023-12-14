#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
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

EXPECTED_GENERATED_FILE_INDENT_0 = """const uint8_t public_key[] = {
0xed, 0xd0, 0x9e, 0xa5, 0xec, 0xe4, 0xed, 0xbe, 0x6c, 0x08, 0xe7, 0x47,
0x09, 0x55, 0x9a, 0x38, 0x29, 0xc5, 0x31, 0x33, 0x22, 0x7b, 0xf4, 0xf0,
0x11, 0x6e, 0x8c, 0x05, 0x2d, 0x02, 0x0e, 0x0e, 0xc3, 0xe0, 0xd8, 0x37,
0xf4, 0xc2, 0x6f, 0xc1, 0x28, 0x80, 0x2f, 0x45, 0x38, 0x1a, 0x23, 0x2b,
0x6d, 0xd5, 0xda, 0x28, 0x60, 0x00, 0x5d, 0xab, 0xe2, 0xa0, 0x83, 0xdb,
0xef, 0x38, 0x55, 0x13
};
"""

EXPECTED_GENERATED_FILE_INDENT_8 = """const uint8_t public_key[] = {
        0xed, 0xd0, 0x9e, 0xa5, 0xec, 0xe4, 0xed, 0xbe, 0x6c, 0x08, 0xe7, 0x47,
        0x09, 0x55, 0x9a, 0x38, 0x29, 0xc5, 0x31, 0x33, 0x22, 0x7b, 0xf4, 0xf0,
        0x11, 0x6e, 0x8c, 0x05, 0x2d, 0x02, 0x0e, 0x0e, 0xc3, 0xe0, 0xd8, 0x37,
        0xf4, 0xc2, 0x6f, 0xc1, 0x28, 0x80, 0x2f, 0x45, 0x38, 0x1a, 0x23, 0x2b,
        0x6d, 0xd5, 0xda, 0x28, 0x60, 0x00, 0x5d, 0xab, 0xe2, 0xa0, 0x83, 0xdb,
        0xef, 0x38, 0x55, 0x13
};
"""


@pytest.fixture
def mocker_existing_file(mocker):
    getsize_data = mocker.Mock()
    getsize_data.side_effect = lambda _: len(PRIVATE_KEY_FILE_NONEMPTY)
    mocker.patch("os.path.getsize", getsize_data)

    exists_data = mocker.Mock()
    exists_data.side_effect = lambda _: True
    mocker.patch("os.path.exists", exists_data)


@pytest.fixture
def default_converter(mocker_existing_file):
    """Converted created only with mandatory arguments, leaving other set to default ones"""
    return KeyConverter(
        input_file="some_input_file",
        output_file="some_output_file",
    )


@pytest.fixture
def mocker_header_and_key(mocker):
    getsize_data = mocker.Mock()
    getsize_data.side_effect = lambda _: 1  # Just ensure it is nonnegative
    mocker.patch("os.path.getsize", getsize_data)

    exists_data = mocker.Mock()
    exists_data.side_effect = lambda _: True
    mocker.patch("os.path.exists", exists_data)

    file_contents = [HEADER_FILE_DATA_NON_EMPTY, PRIVATE_KEY_FILE_NONEMPTY]
    mock_files = [mocker.mock_open(read_data=content).return_value for content in file_contents]
    mock_opener = mocker.mock_open()
    mock_opener.side_effect = mock_files
    mocker.patch("builtins.open", mock_opener)


@pytest.fixture
def mocker_key_and_footer(mocker):
    getsize_data = mocker.Mock()
    getsize_data.side_effect = lambda _: 1  # Just ensure it is nonnegative
    mocker.patch("os.path.getsize", getsize_data)

    exists_data = mocker.Mock()
    exists_data.side_effect = lambda _: True
    mocker.patch("os.path.exists", exists_data)

    file_contents = [PRIVATE_KEY_FILE_NONEMPTY, FOOTER_FILE_DATA_NON_EMPTY]
    mock_files = [mocker.mock_open(read_data=content).return_value for content in file_contents]
    mock_opener = mocker.mock_open()
    mock_opener.side_effect = mock_files
    mocker.patch("builtins.open", mock_opener)


@pytest.fixture
def mocker_header_key_and_footer(mocker):
    getsize_data = mocker.Mock()
    getsize_data.side_effect = lambda _: 1  # Just ensure it is nonnegative
    mocker.patch("os.path.getsize", getsize_data)

    exists_data = mocker.Mock()
    exists_data.side_effect = lambda _: True
    mocker.patch("os.path.exists", exists_data)

    file_contents = [HEADER_FILE_DATA_NON_EMPTY, PRIVATE_KEY_FILE_NONEMPTY, FOOTER_FILE_DATA_NON_EMPTY]
    mock_files = [mocker.mock_open(read_data=content).return_value for content in file_contents]
    mock_opener = mocker.mock_open()
    mock_opener.side_effect = mock_files
    mocker.patch("builtins.open", mock_opener)


@pytest.fixture
def valid_converter(mocker_existing_file):
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
    exists_data = mocker.Mock()
    exists_data.side_effect = lambda _: True
    mocker.patch("os.path.exists", exists_data)

    size_data = mocker.Mock()
    size_data.side_effect = lambda _: 0
    mocker.patch("os.path.getsize", size_data)

    mocked_data = mocker.mock_open(read_data="")
    mocker.patch("builtins.open", mocked_data)


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
    getsize_data = mocker.Mock()
    getsize_data.side_effect = lambda _: len(PRIVATE_KEY_FILE_NONEMPTY)
    mocker.patch("os.path.getsize", getsize_data)

    exists_data = mocker.Mock()
    exists_data.side_effect = lambda _: True
    mocker.patch("os.path.exists", exists_data)

    mocked_data = mocker.mock_open(read_data=PRIVATE_KEY_FILE_NONEMPTY)
    mocker.patch("builtins.open", mocked_data)


def test_validate_invalid_input_file():
    # GIVEN empty input file name
    # WHEN converter is created
    # THEN it raises an exception
    with pytest.raises(FileNotFoundError):
        KeyConverter(input_file="", output_file="some_output_file")


def test_validate_whitespace_input_file(mocker_existing_file):
    # GIVEN input file name consisting of white spaces
    # WHEN converter is created
    # THEN it does not raise an exception
    KeyConverter(input_file=" ", output_file="some_output_file")


def test_validate_invalid_output_file(mocker_existing_file):
    # GIVEN converter created with empty output file name
    converter = KeyConverter(input_file="some_input_file", output_file="")
    # WHEN file contents are prepared
    # THEN it raises an exception
    with pytest.raises(FileNotFoundError):
        converter.prepare_file_contents()


def test_validate_whitespace_output_file(mocker_private_key_file_nonempty):
    # GIVEN converter created with output file name consisting of white spaces
    converter = KeyConverter(input_file="some_input_file", output_file=" ")
    # WHEN file contents are prepared
    # THEN it does not raise exception
    converter.prepare_file_contents()


def test_validate_array_type():
    # GIVEN empty array variable type
    # WHEN converter is created
    # THEN it raises an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", array_type="")


def test_validate_array_name():
    # GIVEN empty array variable name
    # WHEN converter is created
    # THEN it raises an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", array_name="")


def test_validate_length_type():
    # GIVEN empty length variable type
    # WHEN converter is created
    # THEN it raises an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", length_type="")


def test_validate_length_name():
    # GIVEN empty length variable name
    # WHEN converter is created
    # THEN it raises an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", length_name="")


def test_validate_columns_count_zero():
    # GIVEN columns count set to zero
    # WHEN converter is created
    # THEN it raises an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", columns_count=0)


def test_validate_columns_count_negative():
    # GIVEN columns count set to negative value
    # WHEN converter is created
    # THEN it raises an exception
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file", columns_count=-123)


def test_validate_negative_indentation_count(mocker_private_key_file_nonempty):
    # GIVEN indentation count set to -4
    # WHEN converter is created
    # THEN it raises an exception
    with pytest.raises(ValueError):
        KeyConverter(
            input_file="key_private.pem",
            output_file="some_output_file",
            array_name="public_key",
            no_length=True,
            columns_count=12,
            indentation_count=-4,
        )


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
    # THEN it contains the text file contents followed by a newline
    assert text == HEADER_FILE_DATA_NON_EMPTY + "\n\n"


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
    assert text == "\n" + FOOTER_FILE_DATA_NON_EMPTY


def test_modified_use_const(default_converter):
    # GIVEN converter that had no '--no-const' argument passed
    # WHEN modifier text is prepared
    text = default_converter._prepare_modifier()
    # THEN it contains the 'const' modifier
    assert text == "const "


def test_modifier_no_const(mocker_existing_file):
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


def test_array_type_custom(mocker_existing_file):
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


def test_array_variable_custom(mocker_existing_file):
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
    assert text == "};\n"


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
    assert definition == "const uint8_t key_buf[] = {\n"


def test_array_definition_no_const(mocker_existing_file):
    # GIVEN a converter with "--no-const"
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", no_const=True)
    # WHEN array definition is created
    definition = converter._prepare_array_definition()
    # THEN it is as expected
    assert definition == "uint8_t key_buf[] = {\n"


def test_array_definition_custom_type(mocker_existing_file):
    # GIVEN a converter with "char" used as a array type
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", array_type="char")
    # WHEN array definition is created
    definition = converter._prepare_array_definition()
    # THEN it is as expected
    assert definition == "const char key_buf[] = {\n"


def test_array_definition_custom_name(mocker_existing_file):
    # GIVEN a converter with custom array name
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", array_name="foo")
    # WHEN array definition is created
    definition = converter._prepare_array_definition()
    # THEN it is as expected
    assert definition == "const uint8_t foo[] = {\n"


def test_length_definition_default(default_converter):
    # GIVEN default converter
    # WHEN length variable definition is prepared
    text = default_converter._prepare_length_variable()
    # THEN it is as following
    assert text == "\nconst size_t key_len = sizeof(key_buf);\n"


def test_length_definition_no_const(mocker_existing_file):
    # GIVEN converter with "--no-const"
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", no_const=True)
    # WHEN length variable definition is prepared
    text = converter._prepare_length_variable()
    # THEN it is as following
    assert text == "\nsize_t key_len = sizeof(key_buf);\n"


def test_length_definition_custom_type(mocker_existing_file):
    # GIVEN converter with custom length type
    converter = KeyConverter(input_file="some_input_file", output_file="some_output_file", length_type="uint32_t")
    # WHEN length variable definition is prepared
    text = converter._prepare_length_variable()
    # THEN it is as following
    assert text == "\nconst uint32_t key_len = (uint32_t) sizeof(key_buf);\n"


def test_length_definition_custom_name(mocker_existing_file):
    # GIVEN converter with custom length name
    converter = KeyConverter(
        input_file="some_input_file", output_file="some_output_file", length_name="my_fancy_length_name"
    )
    # WHEN length variable definition is prepared
    text = converter._prepare_length_variable()
    # THEN it is as following
    assert text == "\nconst size_t my_fancy_length_name = sizeof(key_buf);\n"


def test_length_definition_no_length(mocker_existing_file):
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
    contents = converter.prepare_file_contents()
    # THEN they match original content generated using suit-tool
    assert contents == EXPECTED_GENERATED_FILE_ORIGINAL


def test_file_creation_original(tmp_path):
    # GIVEN converter with particular configuration
    out_file = tmp_path / "some_output_file"
    converter = KeyConverter(
        # TODO: Find a way to not depend on existence of real key file...
        input_file="key_private.pem",
        output_file=str(out_file),
        array_name="public_key",
        no_length=True,
        columns_count=12,
    )
    # WHEN C file is created
    converter.generate_c_file()

    # THEN its contents match the ones generated using suit-tool
    with open(out_file, "r") as fd:
        generated = fd.read()
    assert generated == EXPECTED_GENERATED_FILE_ORIGINAL


def test_nonexisting_input_file():
    # GIVEN nonexisting input file
    # WHEN converter is created
    # THEN appropriate exception is raised
    with pytest.raises(FileNotFoundError):
        KeyConverter(input_file="nonexisting", output_file="missing")


def test_empty_input_file(mocker_empty_file):
    # GIVEN empty input file
    # WHEN converter is created
    # THEN appropriate exception is raised
    with pytest.raises(ValueError):
        KeyConverter(input_file="some_input_file", output_file="some_output_file")


def test_file_contents_with_header(mocker_header_and_key):
    # GIVEN converter with input file and header file
    converter = KeyConverter(
        input_file="input_file",
        output_file="some_output_file",
        header_file="header_file",
        array_name="public_key",
        no_length=True,
        columns_count=12,
    )
    # WHEN C file contents are prepared
    contents = converter.prepare_file_contents()
    # THEN the contents hold both header file and expected key data
    assert contents == HEADER_FILE_DATA_NON_EMPTY + "\n\n" + EXPECTED_GENERATED_FILE_ORIGINAL


def test_file_contents_with_footer(mocker_key_and_footer):
    # GIVEN converter with input file and footer file
    converter = KeyConverter(
        input_file="input_file",
        output_file="some_output_file",
        footer_file="footer_file",
        array_name="public_key",
        no_length=True,
        columns_count=12,
    )
    # WHEN C file contents are prepared
    contents = converter.prepare_file_contents()
    # THEN the contents hold both expected key data and footer contents
    assert contents == EXPECTED_GENERATED_FILE_ORIGINAL + "\n" + FOOTER_FILE_DATA_NON_EMPTY


def test_file_contents_with_header_and_footer(mocker_header_key_and_footer):
    # GIVEN converter with input file and footer file
    converter = KeyConverter(
        input_file="input_file",
        output_file="some_output_file",
        header_file="header_file",
        footer_file="footer_file",
        array_name="public_key",
        no_length=True,
        columns_count=12,
    )
    # WHEN C file contents are prepared
    contents = converter.prepare_file_contents()
    # THEN the contents hold both expected key data and footer contents
    assert (
        contents
        == HEADER_FILE_DATA_NON_EMPTY + "\n\n" + EXPECTED_GENERATED_FILE_ORIGINAL + "\n" + FOOTER_FILE_DATA_NON_EMPTY
    )


def test_file_contents_indentation_0(mocker_private_key_file_nonempty):
    # GIVEN converter with indentation count set to 0
    converter = KeyConverter(
        input_file="key_private.pem",
        output_file="some_output_file",
        array_name="public_key",
        no_length=True,
        columns_count=12,
        indentation_count=0,
    )
    # WHEN file contents are generated
    contents = converter.prepare_file_contents()
    # THEN they match expected content
    assert contents == EXPECTED_GENERATED_FILE_INDENT_0


def test_file_contents_indentation_8(mocker_private_key_file_nonempty):
    # GIVEN converter with indentation count set to 8
    converter = KeyConverter(
        input_file="key_private.pem",
        output_file="some_output_file",
        array_name="public_key",
        no_length=True,
        columns_count=12,
        indentation_count=8,
    )
    # WHEN file contents are generated
    contents = converter.prepare_file_contents()
    # THEN they match expected content
    assert contents == EXPECTED_GENERATED_FILE_INDENT_8
