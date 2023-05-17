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

signed_envelope_input = (
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
malformed_envelope_input = b"\x00"

expected_boot_storage = (
    ":020000040E1FCD\n:10E000005555AAAA00000000000000000000000012\n:10E0100000000000000000000000000"
    "00000000000\n:0DE0200000000000000000000000000000F3\n:10F00000D86BA2025873825824822F5820047E1B8"
    "A\n:10F01000F1CDA7DDAEC8172D4208A234BD59CFDD12\n:10F020005DD6708B9FDAF9204A0D9E5F94584AD2C4\n:"
    "10F030008443A10126A0F65840B7185C787E237E51\n:10F0400035BE50893722A07D56EF25D7A55C032712\n:10F0"
    "50006049A410FDB57991C8653B1F1C872494B5\n:10F06000A3733B54D0CD0DA13FA46592FBE5375C63\n:10F07000"
    "869AB7A182ADE381490358B7A70101027F\n:10F080000103586CA2028184414D4102451A0E0AC7\n:10F09000A000"
    "451A000560000458558614A40150CC\n:10F0A0002BDC1C07E0D15484BE5063174D5A74C347\n:10F0B00002508520"
    "EA9C515E57798B5FBDAD67DEBB\n:10F0C000C7D9035824822F582066687AADF862BDEC\n:10F0D000776C8FC18B8E"
    "9F8E20089714856EE233DC\n:10F0E000B3902A591D0D5F29250E1820010F020F1C\n:10F0F000074382030F094382"
    "170211528614A11598\n:10F10000692366696C652E62696E1502030F1782AA\n:10F110002F5820F812CC10C34951"
    "1C89D0D9381B64\n:10F12000330CF481F00DBA6FBB4FA2D92F4CED9B7D\n:03F13000CCC01838\n:00000001FF\n"
)
expected_update_storage = (
    ":020000040E1FCD\n:10E00000AAAA55550000100EF30100000000000000\n:10E01000000000000000000000000"
    "0000000000000\n:0DE0200000000000000000000000000000F3\n:00000001FF\n"
)
expected_update_dfu_partition = (
    ":020000040E10DC\n:10000000D86BA4025873825824822F5820047E1B78\n:10001000F1CDA7DDAEC8172"
    "D4208A234BD59CFDD02\n:100020005DD6708B9FDAF9204A0D9E5F94584AD2B4\n:100030008443A10126A0F65840B7185C787E237"
    "E41\n:1000400035BE50893722A07D56EF25D7A55C032702\n:100050006049A410FDB57991C8653B1F1C872494A5\n:10006000A3"
    "733B54D0CD0DA13FA46592FBE5375C53\n:10007000869AB7A182ADE381490358B7A70101026F\n:100080000103586CA202818441"
    "4D4102451A0E0AB7\n:10009000A000451A000560000458558614A40150BC\n:1000A0002BDC1C07E0D15484BE5063174D5A74C337"
    "\n:1000B00002508520EA9C515E57798B5FBDAD67DEAB\n:1000C000C7D9035824822F582066687AADF862BDDC\n:1000D000776C8"
    "FC18B8E9F8E20089714856EE233CC\n:1000E000B3902A591D0D5F29250E1820010F020F0C\n:1000F000074382030F09438217021"
    "1528614A11588\n:10010000692366696C652E62696E1502030F17829A\n:100110002F5820F812CC10C349511C89D0D9381B54\n:"
    "10012000330CF481F00DBA6FBB4FA2D92F4CED9B6D\n:10013000CCC018175891A184414D4102451A0E0AAE\n:10014000A000451A"
    "00056000A60178184E6F726481\n:1001500069632053656D69636F6E647563746F7254\n:1001600020415341026E6E5246353432"
    "305F637027\n:1001700075617070036D6E6F7264696373656D692C\n:100180002E6E6F04781C546865206E5246353432EA\n:100"
    "1900030206170706C69636174696F6E20636F89\n:1001A000726505781A53616D706C65206170706CB2\n:1001B00069636174696"
    "F6E20636F726520465706CC\n:1001C0006676312E302E30692366696C652E626941\n:1001D0006E5820000000000000000000000"
    "0000039\n:1001E000000000000000000000000000000000000F\n:0301F0000000000C\n:00000001FF\n"
)


def prepare_calls(data):
    """Split data by lines and wrap each line using _Call object for easy assertions; get rid of last newline"""
    return [_Call(("", (f"{line}\n",))) for line in data.split("\n")[:-1]]


@pytest.mark.parametrize("nb_of_caches", range(MAX_CACHE_COUNT + 1))
def test_struct_format(nb_of_caches):
    caches_format = "II" * nb_of_caches
    format = "<IIIB" + caches_format
    assert ImageCreator._prepare_suit_storage_struct_format(nb_of_caches) == format


@pytest.mark.parametrize("nb_of_caches", range(MAX_CACHE_COUNT + 1))
def test_update_candidate_info_for_boot(nb_of_caches):
    suit_storage_bytes = b"\x55\x55\xAA\xAA\x00\x00\x00\x00\x00\x00\x00\x00"
    used_cache_bytes = b"\x00"
    caches_bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00" * nb_of_caches

    expected_bytes = suit_storage_bytes + used_cache_bytes + caches_bytes

    assert ImageCreator._prepare_update_candidate_info_for_boot(nb_of_caches) == expected_bytes


@pytest.mark.parametrize("nb_of_caches", range(MAX_CACHE_COUNT + 1))
@pytest.mark.parametrize("address", addresses)
@pytest.mark.parametrize("size", sizes)
def test_update_candidate_info_for_update(address, size, nb_of_caches):
    magic_bytes = b"\xAA\xAA\x55\x55"
    address_bytes = addresses[address]
    size_bytes = sizes[size]

    suit_storage_bytes = magic_bytes + address_bytes + size_bytes

    used_cache_bytes = b"\x00"
    caches_bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00" * nb_of_caches

    expected_bytes = suit_storage_bytes + used_cache_bytes + caches_bytes

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


def test_boot_subcommand_success(mocker):
    io_mock = mocker.mock_open(read_data=signed_envelope_input)
    mocker.patch("builtins.open", io_mock)

    cmd_image_main(
        image="boot",
        input_file="some_input",
        storage_output_file="some_output.hex",
        update_candidate_info_address=0x0E1FE000,
        envelope_address=0x0E1FF000,
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
        update_candidate_info_address=0x0E1FE000,
        envelope_address=0x0E1FF000,
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
            update_candidate_info_address=0x0E1FE000,
            envelope_address=0x0E1FF000,
            dfu_partition_output_file="some_dfu_partition_output",
            dfu_partition_address=0x0E100000,
            dfu_max_caches=4,
        )
