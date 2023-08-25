# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for cmd_image.py implementation."""

import pytest

from suit_generator.cmd_image import ImageCreator
from suit_generator.cmd_image import main as cmd_image_main
from suit_generator.exceptions import GeneratorError, SUITError

from unittest.mock import _Call

MAX_CACHE_COUNT = 16

addresses = {0x00000000: b"\x00\x00\x00\x00", 0xDEADBEEF: b"\xEF\xBE\xAD\xDE", 0xFFFFFFFF: b"\xFF\xFF\xFF\xFF"}
sizes = {0x00000000: b"\x00\x00\x00\x00", 0x01020304: b"\x04\x03\x02\x01", 0xFFFFFFFF: b"\xFF\xFF\xFF\xFF"}

signed_envelope_without_class_id_input = (
    b"\xd8k\xa4\x02Xs\x82X$\x82/X \x04~\x1b\xf1\xcd\xa7\xdd\xae\xc8\x17-B\x08\xa24\xbdY\xcf\xdd]"
    b'\xd6p\x8b\x9f\xda\xf9 J\r\x9e_\x94XJ\xd2\x84C\xa1\x01&\xa0\xf6X@\xb7\x18\\x~#~5\xbeP\x897"'
    b"\xa0}V\xef%\xd7\xa5\\\x03'`I\xa4\x10\xfd\xb5y\x91\xc8e;\x1f\x1c\x87$\x94\xa3s;T\xd0\xcd\r\xa1"
    b"?\xa4e\x92\xfb\xe57\\\x86\x9a\xb7\xa1\x82\xad\xe3\x81I\x03X\xb7\xa7\x01\x01\x02\x01\x03Xl\xa2"
    b"\x02\x81\x84AMA\x02E\x1a\x0e\n\xa0\x00E\x1a\x00\x05`\x00\x04XU\x86\x14\xa4\x01P+\xdc\x1c\x07"
    b"\xe0\xd1T\x84\xbePc\x17MZt\xc3\x02P\x85 \xea\x9cQ^Wy\x8b_\xbd\xadg\xde\xc7\xd9\x03X$\x82/X fh"
    b"z\xad\xf8b\xbdwl\x8f\xc1\x8b\x8e\x9f\x8e \x08\x97\x14\x85n\xe23\xb3\x90*Y\x1d\r_)%\x0e\x18 "
    b"\x01\x0f\x02\x0f\x07C\x82\x03\x0f\tC\x82\x17\x02\x11R\x86\x14\xa1\x15i#file.bin\x15\x02\x03"
    b"\x0f\x17\x82/X \xf8\x12\xcc\x10\xc3IQ\x1c\x89\xd0\xd98\x1b3\x0c\xf4\x81\xf0\r\xbao\xbbO\xa2"
    b"\xd9/L\xed\x9b\xcc\xc0\x18\x17X\x91\xa1\x84AMA\x02E\x1a\x0e\n\xa0\x00E\x1a\x00\x05`\x00\xa6"
    b"\x01x\x18Nordic Semiconductor ASA\x02nnRF5420_cpuapp\x03mnordicsemi.no\x04x\x1cThe nRF5420 ap"
    b"plication core\x05x\x1aSample application core FW\x06fv1.0.0i#file.binX \x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
)
signed_envelope_input = (
    b"\xd8k\xa3\x02X'\x81X$\x82/X \x06F*\xde\x88\x1cf\xd3AR~V\xcc\x04TW\xe9\x8d\x15\xadD\xbb\x94w!9"
    b"\xccL\xe7\xa7I\x86\x03X\xbf\xa7\x01\x01\x02\x01\x03Xx\xa2\x02\x82\x82ADA\x00\x84AMA\x02E\x1a"
    b"\x0e\n\xa0\x00E\x1a\x00\x07\xf8\x00\x04X\\\x8c\x0c\x01\x14\xa2\x01Pv\x17\xda\xa5q\xfdZ\x85"
    b"\x8f\x94\xe2\x8ds\\\xe9\xf4\x02P\x08\xc1\xb5\x99U\xe8_\xbc\x9ev{\xc2\x9c\xe1\xb0M\x01\x0f\x02"
    b"\x0f\x0c\xf5\x14\xa2\x03X$\x82/X f\xf5\xc2,\xbe\xaev\xdcc\xd8\x08\xb7\x0fv\t\xc2\xf2\xc9&\x87"
    b"\\f3\xaf\xe3\x91\r_\x97\xc5\x02j\x0e\x19\xd1\xf4\x07E\x84\x0c\x01\x03\x0f\tE\x84\x0c\x01\x17"
    b"\x02\x11X\x19\x90\x0c\x00\x14\xa1\x15d#app\x15\x02\x03\x0f\x0c\x01\x14\xa1\x16\x00\x16\x02"
    b"\x03\x0f\x05\x82AIP\x08\xc1\xb5\x99U\xe8_\xbc\x9ev{\xc2\x9c\xe1\xb0M\x17X\x92\xa1\x84AMA\x02"
    b"E\x1a\x0e\n\xa0\x00C\x19\x01\x00\xa6\x01x\x18Nordic Semiconductor ASA\x02onRF54H20_cpuapp\x03"
    b"nnordicsemi.com\x04x\x1dThe nRF54H20 application core\x05x\x1aSample application core FW\x06f"
    b"v1.0.0"
)
malformed_envelope_input = b"\x00"

expected_boot_storage = (
    ":020000040E1ECE\n"
    ":10EC0000AA55AA5500000000000000000000000006\n"
    ":10EC100000000000000000000000000000000000F4\n"
    ":10EC200000000000000000000000000000000000E4\n"
    ":10ED8000A300010118DF0258EFD86BA202582781B7\n"
    ":10ED90005824822F582006462ADE881C66D341520A\n"
    ":10EDA0007E56CC045457E98D15AD44BB9477213978\n"
    ":10EDB000CC4CE7A749860358BFA7010102010358BD\n"
    ":10EDC00078A20282824144410084414D4102451AA9\n"
    ":10EDD0000E0AA000451A0007F80004585C8C0C01CC\n"
    ":10EDE00014A201507617DAA571FD5A858F94E28D31\n"
    ":10EDF000735CE9F4025008C1B59955E85FBC9E7692\n"
    ":10EE00007BC29CE1B04D010F020F0CF514A2035818\n"
    ":10EE100024822F582066F5C22CBEAE76DC63D8085B\n"
    ":10EE2000B70F7609C2F2C926875C6633AFE3910D4E\n"
    ":10EE30005F97C5026A0E19D1F40745840C01030FD0\n"
    ":10EE40000945840C011702115819900C0014A115E2\n"
    ":10EE500064236170701502030F0C0114A1160016D3\n"
    ":10EE600002030F058241495008C1B59955E85FBCBE\n"
    ":08EE70009E767BC29CE1B04DCF\n"
    ":00000001FF\n"
)

expected_update_storage = (
    ":020000040E1ECE\n"
    ":10EC0000AA55AA55010000000000100E8401000062\n"
    ":10EC100000000000000000000000000000000000F4\n"
    ":10EC200000000000000000000000000000000000E4\n"
    ":00000001FF\n"
)
expected_update_dfu_partition = (
    ":020000040E10DC\n"
    ":10000000D86BA3025827815824822F582006462AED\n"
    ":10001000DE881C66D341527E56CC045457E98D15B8\n"
    ":10002000AD44BB94772139CC4CE7A749860358BF30\n"
    ":10003000A701010201035878A202828241444100D3\n"
    ":1000400084414D4102451A0E0AA000451A0007F8E6\n"
    ":100050000004585C8C0C0114A201507617DAA571CB\n"
    ":10006000FD5A858F94E28D735CE9F4025008C1B5A6\n"
    ":100070009955E85FBC9E767BC29CE1B04D010F02B2\n"
    ":100080000F0CF514A2035824822F582066F5C22CB9\n"
    ":10009000BEAE76DC63D808B70F7609C2F2C92687F0\n"
    ":1000A0005C6633AFE3910D5F97C5026A0E19D1F418\n"
    ":1000B0000745840C01030F0945840C0117021158F0\n"
    ":1000C00019900C0014A11564236170701502030FC0\n"
    ":1000D0000C0114A116001602030F058241495008B5\n"
    ":1000E000C1B59955E85FBC9E767BC29CE1B04D17C7\n"
    ":1000F0005892A184414D4102451A0E0AA0004319AD\n"
    ":100100000100A60178184E6F726469632053656D13\n"
    ":1001100069636F6E647563746F7220415341026F3F\n"
    ":100120006E524635344832305F63707561707003CB\n"
    ":100130006E6E6F7264696373656D692E636F6D04B3\n"
    ":10014000781D546865206E5246353448323020613F\n"
    ":1001500070706C69636174696F6E20636F7265059E\n"
    ":10016000781A53616D706C65206170706C696361A1\n"
    ":1001700074696F6E20636F7265204657066676312C\n"
    ":040180002E302E30BF\n"
    ":00000001FF\n"
)


def prepare_calls(data):
    """Split data by lines and wrap each line using _Call object for easy assertions; get rid of last newline"""
    return [_Call(("", (f"{line}\n",))) for line in data.split("\n")[:-1]]


@pytest.mark.parametrize("nb_of_caches", range(MAX_CACHE_COUNT + 1))
def test_struct_format(nb_of_caches):
    caches_format = "II" * nb_of_caches
    format = "<IIII" + caches_format
    assert ImageCreator._prepare_suit_storage_struct_format(nb_of_caches) == format


@pytest.mark.parametrize("nb_of_caches", range(MAX_CACHE_COUNT + 1))
def test_update_candidate_info_for_boot(nb_of_caches):
    suit_storage_bytes = b"\xAA\x55\xAA\x55\x00\x00\x00\x00"
    envelope_address_size_bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    caches_bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00" * nb_of_caches

    expected_bytes = suit_storage_bytes + envelope_address_size_bytes + caches_bytes

    assert ImageCreator._prepare_update_candidate_info_for_boot(nb_of_caches) == expected_bytes


def test_update_candidate_info_verify_class_id_offset():
    from suit_generator.envelope import SuitEnvelope
    from suit_generator.suit.envelope import SuitEnvelopeTagged
    from cbor2 import loads as cbor_loads

    # Generate envlope object
    envelope = SuitEnvelope()
    envelope._envelope = SuitEnvelopeTagged.from_cbor(signed_envelope_input).to_obj()

    # Generate storage envelope slot for the envelope
    storage_cbor = ImageCreator._prepare_envelope_slot_binary(envelope)

    # Extract the class ID, based on the offset and minified envelope
    storage_dict = cbor_loads(storage_cbor)
    offset = storage_dict[ImageCreator.ENVELOPE_SLOT_CLASS_ID_OFFSET_KEY]
    envelope_bstr = storage_dict[ImageCreator.ENVELOPE_SLOT_ENVELOPE_BSTR_KEY]

    # RFC4122 uuid5(nordic_vid, 'nRF54H20_sample_app')
    exp_class_id = b"\x08\xc1\xb5\x99\x55\xe8\x5f\xbc\x9e\x76\x7b\xc2\x9c\xe1\xb0\x4d"

    assert envelope_bstr[offset : offset + 16] == exp_class_id


@pytest.mark.parametrize("nb_of_caches", range(MAX_CACHE_COUNT + 1))
@pytest.mark.parametrize("address", addresses)
@pytest.mark.parametrize("size", sizes)
def test_update_candidate_info_for_update(address, size, nb_of_caches):
    magic_bytes = b"\xAA\x55\xAA\x55"
    nregions_bytes = b"\x01\x00\x00\x00"
    address_bytes = addresses[address]
    size_bytes = sizes[size]

    suit_storage_bytes = magic_bytes + nregions_bytes + address_bytes + size_bytes

    caches_bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00" * nb_of_caches

    expected_bytes = suit_storage_bytes + caches_bytes

    assert ImageCreator._prepare_update_candidate_info_for_update(address, size, nb_of_caches) == expected_bytes


def test_unsupported_image_subcommand():
    with pytest.raises(GeneratorError):
        cmd_image_main(
            image="unsupported",
            input_file="",
            storage_output_file="",
            update_candidate_info_address=0,
            envelope_address=0,
            dfu_partition_output_file="",
            dfu_partition_address=0,
            dfu_max_caches=0,
        )


def test_boot_subcommand_nonexisting_input_file():
    with pytest.raises(GeneratorError):
        cmd_image_main(
            image="boot",
            input_file="nonexisting",
            storage_output_file="",
            update_candidate_info_address=0,
            envelope_address=0,
            dfu_partition_output_file="",
            dfu_partition_address=0,
            dfu_max_caches=0,
        )


def test_boot_subcommand_manifest_without_component_id(mocker):
    io_mock = mocker.mock_open(read_data=signed_envelope_without_class_id_input)
    mocker.patch("builtins.open", io_mock)

    with pytest.raises(GeneratorError):
        cmd_image_main(
            image="boot",
            input_file="some_input",
            storage_output_file="some_output.hex",
            update_candidate_info_address=0x0E1EEC00,
            envelope_address=0x0E1EED80,
            dfu_partition_output_file="",
            dfu_partition_address=0,
            dfu_max_caches=4,
        )


def test_boot_subcommand_success(mocker):
    io_mock = mocker.mock_open(read_data=signed_envelope_input)
    mocker.patch("builtins.open", io_mock)

    cmd_image_main(
        image="boot",
        input_file="some_input",
        storage_output_file="some_output.hex",
        update_candidate_info_address=0x0E1EEC00,
        envelope_address=0x0E1EED80,
        dfu_partition_output_file="",
        dfu_partition_address=0,
        dfu_max_caches=4,
    )

    io_mock().read.assert_called_once()
    io_mock().write.assert_has_calls(prepare_calls(expected_boot_storage))


def test_update_subcommand_nonexisting_input_file():
    with pytest.raises(GeneratorError):
        cmd_image_main(
            image="update",
            input_file="nonexisting",
            storage_output_file="",
            update_candidate_info_address=0,
            envelope_address=0,
            dfu_partition_output_file="",
            dfu_partition_address=0,
            dfu_max_caches=0,
        )


def test_update_subcommand_success(mocker):
    io_mock = mocker.mock_open(read_data=signed_envelope_input)

    mocker.patch("builtins.open", io_mock)

    getsize_mock = mocker.Mock()
    getsize_mock.side_effect = lambda _: len(signed_envelope_input)
    mocker.patch("os.path.getsize", getsize_mock)

    cmd_image_main(
        image="update",
        input_file="some_input",
        storage_output_file="some_storage_output",
        update_candidate_info_address=0x0E1EEC00,
        envelope_address=0x0E1EED80,
        dfu_partition_output_file="some_dfu_partition_output",
        dfu_partition_address=0x0E100000,
        dfu_max_caches=4,
    )

    expected_calls = prepare_calls(expected_update_storage) + prepare_calls(expected_update_dfu_partition)

    io_mock().read.assert_called_once()
    io_mock().write.assert_has_calls(expected_calls)


def test_malformed_envelope(mocker):
    io_mock = mocker.mock_open(read_data=malformed_envelope_input)
    mocker.patch("builtins.open", io_mock)

    with pytest.raises(SUITError):
        cmd_image_main(
            image="boot",
            input_file="some_input",
            storage_output_file="some_output.hex",
            update_candidate_info_address=0x0E1FE000,
            envelope_address=0x0E1FF000,
            dfu_partition_output_file="",
            dfu_partition_address=0,
            dfu_max_caches=0,
        )


def test_bin2hex_conversion_error(mocker, monkeypatch):
    io_mock = mocker.mock_open(read_data=signed_envelope_input)

    mocker.patch("builtins.open", io_mock)

    getsize_mock = mocker.Mock()
    getsize_mock.side_effect = lambda _: len(signed_envelope_input)
    mocker.patch("os.path.getsize", getsize_mock)

    def bin2hex_mock(*args, **kwargs):
        """Helper function to return non-zero error code"""
        return 42

    # The intuitive way would be to use 'mocker.patch("intelhex.bin2hex", ...)' but it doesn't mock the bin2hex function
    # when it is imported in tested code by 'from intelhex import bin2hex'.
    # The approach below allows to patch the function regardless of how it is imported in tested code.
    monkeypatch.setattr("intelhex.bin2hex.__code__", bin2hex_mock.__code__)

    with pytest.raises(GeneratorError):
        cmd_image_main(
            image="update",
            input_file="some_input",
            storage_output_file="some_storage_output",
            update_candidate_info_address=0x0E1EEC00,
            envelope_address=0x0E1EED80,
            dfu_partition_output_file="some_dfu_partition_output",
            dfu_partition_address=0x0E100000,
            dfu_max_caches=4,
        )
