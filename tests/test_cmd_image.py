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
    b"\xd8k\xa4\x02Xs\x82X$\x82/X \xf1:\x80\x8f\xa3\x16)\x95\xd4G\xd3\xde\xe8\r\xa6\xb6\n\xcc\x03"
    b"\xb8m\xdc{\x12Z\x9b\xe5\x9e\xa0\xddL]XJ\xd2\x84C\xa1\x01&\xa0\xf6X@0!\n\xd4\xb7=\x13\xfc\xbaF"
    b"*\xb02\xa7p\xb5s\x83@6}\x96Q\x1d\xdc\xb3)\x07@<0\x99\xd7J\x1c\xaa\x8f_6\xf3\x08\xaa\xa7\xde"
    b"\x8fG\xedJ\xdd\xcdO^!$\x94\xa2U\xad\xb4\xb6\x8bC\xa8S\x03X\xba\xa7\x01\x01\x02\x01\x03Xo\xa2"
    b"\x02\x81\x84DcMEMA\x02E\x1a\x0e\n\xa0\x00E\x1a\x00\x05`\x00\x04XU\x86\x14\xa4\x01Pv\x17\xda"
    b"\xa5q\xfdZ\x85\x8f\x94\xe2\x8ds\\\xe9\xf4\x02P\x08\xc1\xb5\x99U\xe8_\xbc\x9ev{\xc2\x9c\xe1\xb0"
    b"M\x03X$\x82/X fhz\xad\xf8b\xbdwl\x8f\xc1\x8b\x8e\x9f\x8e \x08\x97\x14\x85n\xe23\xb3\x90*Y\x1d"
    b"\r_)%\x0e\x18 \x01\x0f\x02\x0f\x07C\x82\x03\x0f\tC\x82\x17\x02\x11R\x86\x14\xa1\x15i#file.bin"
    b"\x15\x02\x03\x0f\x17\x82/X \xd6%\x82'\x08\xfb\x1b\x18x\x8c\x98waBt\xf0\x966\xa7\xe0yN\xbd\x87"
    b"\x9b\xa1\x90*\xf1K8\x05\x17X\x97\xa1\x84DcMEMA\x02E\x1a\x0e\n\xa0\x00E\x1a\x00\x05`\x00\xa6"
    b"\x01x\x18Nordic Semiconductor ASA\x02onRF54H20_cpuapp\x03nnordicsemi.com\x04x\x1dThe nRF54H20"
    b" application core\x05x\x1aSample application core FW\x06fv1.0.0i#file.binX \x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00"
)
signed_envelope_input = (
    b"\xd8k\xa4\x02Xs\x82X$\x82/X ,\xb17i\xebj\xb3f \x95'\x0e\\\xa6\x8f\xc0\xb5\x9fnd\xf32\xa1)k<"
    b"\xe0\x8e\x9a\xcaO\x7fXJ\xd2\x84C\xa1\x01&\xa0\xf6X@\x1d\x8e\xc1h\xbd\x91\xa5\xb3C5\xb6V=xI\x80"
    b"#\xd9\xd6\xbdh~\xd2\x8a\xa8:\xd7zg\xbf#\x87\x00k\x7f\"\x88V'\x99\xb3\x08ITi\x04\x0e0\xe9A@:"
    b"\xafB\xfd\x16\xd1\xe3\x1cS\x17$\x97\xab\x03X\xda\xa8\x01\x01\x02\x01\x03Xo\xa2\x02\x81\x84DcME"
    b"MA\x02E\x1a\x0e\n\xa0\x00E\x1a\x00\x05`\x00\x04XU\x86\x14\xa4\x01Pv\x17\xda\xa5q\xfdZ\x85\x8f"
    b"\x94\xe2\x8ds\\\xe9\xf4\x02P\x08\xc1\xb5\x99U\xe8_\xbc\x9ev{\xc2\x9c\xe1\xb0M\x03X$\x82/X fhz"
    b"\xad\xf8b\xbdwl\x8f\xc1\x8b\x8e\x9f\x8e \x08\x97\x14\x85n\xe23\xb3\x90*Y\x1d\r_)%\x0e\x18 \x01"
    b"\x0f\x02\x0f\x07C\x82\x03\x0f\tC\x82\x17\x02\x11R\x86\x14\xa1\x15i#file.bin\x15\x02\x03\x0f"
    b"\x17\x82/X \xd6%\x82'\x08\xfb\x1b\x18x\x8c\x98waBt\xf0\x966\xa7\xe0yN\xbd\x87\x9b\xa1\x90*\xf1"
    b"K8\x05\x05\x82LkINSTLD_MFSTP\x08\xc1\xb5\x99U\xe8_\xbc\x9ev{\xc2\x9c\xe1\xb0M\x17X\x97\xa1\x84"
    b"DcMEMA\x02E\x1a\x0e\n\xa0\x00E\x1a\x00\x05`\x00\xa6\x01x\x18Nordic Semiconductor ASA\x02onRF54"
    b"H20_cpuapp\x03nnordicsemi.com\x04x\x1dThe nRF54H20 application core\x05x\x1aSample application"
    b" core FW\x06fv1.0.0i#file.binX \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)
malformed_envelope_input = b"\x00"

expected_boot_storage = (
    ":020000040E1ECE\n"
    ":10EC0000AA55AA5500000000000000000000000006\n"
    ":10EC100000000000000000000000000000000000F4\n"
    ":10EC200000000000000000000000000000000000E4\n"
    ":10ED8000A300010119014602590156D86BA202588D\n"
    ":10ED900073825824822F58202CB13769EB6AB366EE\n"
    ":10EDA0002095270E5CA68FC0B59F6E64F332A12913\n"
    ":10EDB0006B3CE08E9ACA4F7F584AD28443A1012609\n"
    ":10EDC000A0F658401D8EC168BD91A5B34335B65617\n"
    ":10EDD0003D78498023D9D6BD687ED28AA83AD77AB1\n"
    ":10EDE00067BF2387006B7F2288562799B308495451\n"
    ":10EDF00069040E30E941403AAF42FD16D1E31C539D\n"
    ":10EE0000172497AB0358DAA80101020103586FA237\n"
    ":10EE100002818444634D454D4102451A0E0AA0000B\n"
    ":10EE2000451A000560000458558614A40150761751\n"
    ":10EE3000DAA571FD5A858F94E28D735CE9F4025076\n"
    ":10EE400008C1B59955E85FBC9E767BC29CE1B04D88\n"
    ":10EE5000035824822F582066687AADF862BD776C1B\n"
    ":10EE60008FC18B8E9F8E20089714856EE233B390EE\n"
    ":10EE70002A591D0D5F29250E1820010F020F074387\n"
    ":10EE800082030F094382170211528614A1156923C8\n"
    ":10EE900066696C652E62696E1502030F17822F5822\n"
    ":10EEA00020D625822708FB1B18788C98776142743E\n"
    ":10EEB000F09636A7E0794EBD879BA1902AF14B389A\n"
    ":10EEC0000505824C6B494E53544C445F4D46535498\n"
    ":10EED0005008C1B59955E85FBC9E767BC29CE1B0F5\n"
    ":01EEE0004DE4\n"
    ":00000001FF\n"
)

expected_update_storage = (
    ":020000040E1ECE\n"
    ":10EC0000AA55AA55010000000000100E1C020000C9\n"
    ":10EC100000000000000000000000000000000000F4\n"
    ":10EC200000000000000000000000000000000000E4\n"
    ":00000001FF\n"
)
expected_update_dfu_partition = (
    ":020000040E10DC\n"
    ":10000000D86BA4025873825824822F58202CB13701\n"
    ":1000100069EB6AB3662095270E5CA68FC0B59F6E0C\n"
    ":1000200064F332A1296B3CE08E9ACA4F7F584AD2C2\n"
    ":100030008443A10126A0F658401D8EC168BD91A53C\n"
    ":10004000B34335B6563D78498023D9D6BD687ED2B4\n"
    ":100050008AA83AD77A67BF2387006B7F2288562702\n"
    ":1000600099B308495469040E30E941403AAF42FD62\n"
    ":1000700016D1E31C53172497AB0358DAA8010102E9\n"
    ":100080000103586FA202818444634D454D410245EE\n"
    ":100090001A0E0AA000451A0005600004585586147F\n"
    ":1000A000A401507617DAA571FD5A858F94E28D73FD\n"
    ":1000B0005CE9F4025008C1B59955E85FBC9E767BB7\n"
    ":1000C000C29CE1B04D035824822F582066687AAD57\n"
    ":1000D000F862BD776C8FC18B8E9F8E200897148538\n"
    ":1000E0006EE233B3902A591D0D5F29250E182001A9\n"
    ":1000F0000F020F074382030F094382170211528632\n"
    ":1001000014A115692366696C652E62696E15020378\n"
    ":100110000F17822F5820D625822708FB1B18788CB2\n"
    ":100120009877614274F09636A7E0794EBD879BA11F\n"
    ":10013000902AF14B380505824C6B494E53544C4480\n"
    ":100140005F4D4653545008C1B59955E85FBC9E7643\n"
    ":100150007BC29CE1B04D175897A18444634D454D37\n"
    ":100160004102451A0E0AA000451A00056000A601CA\n"
    ":1001700078184E6F726469632053656D69636F6EA2\n"
    ":10018000647563746F7220415341026F6E5246353D\n"
    ":10019000344832305F637075617070036E6E6F72D9\n"
    ":1001A00064696373656D692E636F6D04781D5468AF\n"
    ":1001B00065206E52463534483230206170706C696B\n"
    ":1001C000636174696F6E20636F726505781A53619D\n"
    ":1001D0006D706C65206170706C69636174696F6EBD\n"
    ":1001E00020636F7265204657066676312E302E30BA\n"
    ":1001F000692366696C652E62696E582000000000F4\n"
    ":1002000000000000000000000000000000000000EE\n"
    ":0C021000000000000000000000000000E2\n"
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
