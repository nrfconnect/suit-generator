# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for cmd_image.py implementation."""

import pytest
import pathlib
import os

import yaml

from suit_generator.cmd_image import ImageCreator, EnvelopeStorageNrf54h20
from suit_generator.cmd_image import main as cmd_image_main
from suit_generator.exceptions import GeneratorError, SUITError
from suit_generator.suit.envelope import SuitEnvelopeTagged

from unittest.mock import _Call

TEMP_DIRECTORY = pathlib.Path("test_test_data")

MAX_CACHE_COUNT = 16

addresses = {0x00000000: b"\x00\x00\x00\x00", 0xDEADBEEF: b"\xEF\xBE\xAD\xDE", 0xFFFFFFFF: b"\xFF\xFF\xFF\xFF"}
sizes = {0x00000000: b"\x00\x00\x00\x00", 0x01020304: b"\x04\x03\x02\x01", 0xFFFFFFFF: b"\xFF\xFF\xFF\xFF"}

signed_envelope_without_class_id_input = (
    b"\xd8k\xa4\x02X'\x81X$\x82/X 7d\x90\xc1\xa5\x84\xc1\xed\xeeO\x0f\xd6\xad\xc5t\xb0\x1dr\xb5r"
    b"\xa8\x8a\xdaA\x95\xff\xa9\x88O\xb2w\x1e\x03X\xbb\xa7\x01\x01\x02\x01\x03Xp\xa2\x02\x81\x84DcM"
    b"EMA\x02E\x1a\x0e\n\xa0\x00E\x1a\x00\x05`\x00\x04XV\x86\x14\xa4\x01Pv\x17\xda\xa5q\xfdZ\x85"
    b"\x8f\x94\xe2\x8ds\\\xe9\xf4\x02P\x08\xc1\xb5\x99U\xe8_\xbc\x9ev{\xc2\x9c\xe1\xb0M\x03X$\x82"
    b"/X _\xc3T\xbf\x8e\x8cP\xfbO\xbc,\xfa\xeb\x04SA\xc9\x80m\xea\xbd\xcbAT\xfby\xcc\xa4\xf0\xc9"
    b"\x8c\x12\x0e\x19\x01\x00\x01\x0f\x02\x0f\x07C\x82\x03\x0f\tC\x82\x17\x02\x11R\x86\x14\xa1\x15"
    b"i#file.bin\x15\x02\x03\x0f\x17\x82/X Y-\x8d\r\xf0\x93\xd7\x1d6\x82\x85rUd^\x1bV@8&HDF\x04\xff"
    b"\xd5j \xd8O\xe6\xdb\x17X\x9b\xa1ben\xa1\x84DcMEMA\x02E\x1a\x0e\n\xa0\x00E\x1a\x00\x05`\x00"
    b"\xa6\x01x\x18Nordic Semiconductor ASA\x02onRF54H20_cpuapp\x03nnordicsemi.com\x04x\x1dThe nRF5"
    b"4H20 application core\x05x\x1aSample application core FW\x06fv1.0.0i#file.binY\x01\x00\xc7"
    b"\x9c\xab\x9d\xe83\x7f0\x14\xeb\xac\x02\xaf&\x01^\x80m\x88\xa1\xdb\x11\xa71\xdf\xa6\xec\xcb"
    b"\x9bH\r\xc84@m0\x86}\xe8\x1b\xec<\xf5@\xd0H\x18\x82\x11\x9d|?l\xe5\x8f\xf1\xd3]\xe1Q\xf7j\x0f"
    b'\xaf\x0b\xbdL_\xa54\x1af\xdb"\xecc\xedK\xab\xc7\xc8\xf7Y\xd8\xd6\x9e\xecq\x1b$ \xb9\xae\xe1;'
    b'\xfc\xae\xb8w\xac\xa4W4\x97\x84OX\xd5h\x08o\xe3\x9c~\x1b\xd78"\x98H\xf8zg\xb2\xd9\xac\xc54'
    b"\xc1'\x82\x8eBy\x84!7LAJ\x0f\xe2\x7f\xa0j\x19\x13=R\"\x7f\xd6/q\x12v\xab%\x9c\xfcg\x08\x03|"
    b"\xdb\x18\xe6E\xf8\x99\xc2\x9e,\xe3\x9b%\xa9{\t\xff\x00W&\x08\n\x11B\xcf\x82\xa2k*\x99\xf9q"
    b"\x9d\x14\x19\\\\x1`BJ\x18\x1f\xecxj\x9a|O\xcf\xe8Z)e\xcd\x01;mS\xbb\xc6\xdb\xda\xd5\x8f\xf7"
    b"\xf4\xd9\xb9\n\x03K\xff3\xab;\xc5\xaf\xd0\xb8,\x0fj\xa9\x11\xb0\xe8W\x8c\x92S\x81"
)
signed_envelope_input = (
    b"\xd8k\xa4\x02X'\x81X$\x82/X 0EH{\xd1\xb4Q\xab\xf56\x01\x06\x8e#\x81\xafn\xe3g)xn.\x12\x89"
    b"\xb2\x15x\xb5\xcf\xef\xfe\x03X\xdb\xa8\x01\x01\x02\x01\x03Xp\xa2\x02\x81\x84DcMEMA\x02E\x1a"
    b"\x0e\n\xa0\x00E\x1a\x00\x05`\x00\x04XV\x86\x14\xa4\x01Pv\x17\xda\xa5q\xfdZ\x85\x8f\x94\xe2"
    b"\x8ds\\\xe9\xf4\x02P\x08\xc1\xb5\x99U\xe8_\xbc\x9ev{\xc2\x9c\xe1\xb0M\x03X$\x82/X _\xc3T\xbf"
    b"\x8e\x8cP\xfbO\xbc,\xfa\xeb\x04SA\xc9\x80m\xea\xbd\xcbAT\xfby\xcc\xa4\xf0\xc9\x8c\x12\x0e\x19"
    b"\x01\x00\x01\x0f\x02\x0f\x07C\x82\x03\x0f\tC\x82\x17\x02\x11R\x86\x14\xa1\x15i#file.bin\x15"
    b"\x02\x03\x0f\x17\x82/X Y-\x8d\r\xf0\x93\xd7\x1d6\x82\x85rUd^\x1bV@8&HDF\x04\xff\xd5j \xd8O"
    b"\xe6\xdb\x05\x82LkINSTLD_MFSTP\x08\xc1\xb5\x99U\xe8_\xbc\x9ev{\xc2\x9c\xe1\xb0M\x17X\x9b\xa1b"
    b"en\xa1\x84DcMEMA\x02E\x1a\x0e\n\xa0\x00E\x1a\x00\x05`\x00\xa6\x01x\x18Nordic Semiconductor AS"
    b"A\x02onRF54H20_cpuapp\x03nnordicsemi.com\x04x\x1dThe nRF54H20 application core\x05x\x1aSample"
    b" application core FW\x06fv1.0.0i#file.binY\x01\x00\xc7\x9c\xab\x9d\xe83\x7f0\x14\xeb\xac\x02"
    b"\xaf&\x01^\x80m\x88\xa1\xdb\x11\xa71\xdf\xa6\xec\xcb\x9bH\r\xc84@m0\x86}\xe8\x1b\xec<\xf5@"
    b'\xd0H\x18\x82\x11\x9d|?l\xe5\x8f\xf1\xd3]\xe1Q\xf7j\x0f\xaf\x0b\xbdL_\xa54\x1af\xdb"\xecc\xed'
    b"K\xab\xc7\xc8\xf7Y\xd8\xd6\x9e\xecq\x1b$ \xb9\xae\xe1;\xfc\xae\xb8w\xac\xa4W4\x97\x84OX\xd5h"
    b"\x08o\xe3\x9c~\x1b\xd78\"\x98H\xf8zg\xb2\xd9\xac\xc54\xc1'\x82\x8eBy\x84!7LAJ\x0f\xe2\x7f\xa0"
    b'j\x19\x13=R"\x7f\xd6/q\x12v\xab%\x9c\xfcg\x08\x03|\xdb\x18\xe6E\xf8\x99\xc2\x9e,\xe3\x9b%\xa9'
    b"{\t\xff\x00W&\x08\n\x11B\xcf\x82\xa2k*\x99\xf9q\x9d\x14\x19\\\\x1`BJ\x18\x1f\xecxj\x9a|O\xcf"
    b"\xe8Z)e\xcd\x01;mS\xbb\xc6\xdb\xda\xd5\x8f\xf7\xf4\xd9\xb9\n\x03K\xff3\xab;\xc5\xaf\xd0\xb8,"
    b"\x0fj\xa9\x11\xb0\xe8W\x8c\x92S\x81"
)
malformed_envelope_input = b"\x00"

expected_boot_storage = (
    # Empty update candidate info (0x0E1E9340 - 0x0E1E9380)
    # Uninitialized NVV area (0x0E1E9380 - 0x0E1E9400)
    # Application local 1 manifest slot (0x0E1EA400)
    ":10A40000A300010118FB0259010BD86BA2025827C7\n"
    ":10A41000815824822F58203045487BD1B451ABF568\n"
    ":10A420003601068E2381AF6EE36729786E2E12897E\n"
    ":10A43000B21578B5CFEFFE0358DBA8010102010386\n"
    ":10A440005870A202818444634D454D4102451A0E65\n"
    ":10A450000AA000451A000560000458568614A4019D\n"
    ":10A46000507617DAA571FD5A858F94E28D735CE9F9\n"
    ":10A47000F4025008C1B59955E85FBC9E767BC29C3A\n"
    ":10A48000E1B04D035824822F58205FC354BF8E8CF7\n"
    ":10A4900050FB4FBC2CFAEB045341C9806DEABDCB95\n"
    ":10A4A0004154FB79CCA4F0C98C120E190100010FA4\n"
    ":10A4B000020F074382030F094382170211528614C9\n"
    ":10A4C000A115692366696C652E62696E1502030F1A\n"
    ":10A4D00017822F5820592D8D0DF093D71D36828568\n"
    ":10A4E0007255645E1B5640382648444604FFD56AC0\n"
    ":10A4F00020D84FE6DB05824C6B494E53544C445FE9\n"
    ":10A500004D4653545008C1B59955E85FBC9E767BC3\n"
    ":10A51000C29CE1B04DFFFFFFFFFFFFFFFFFFFFFF0A\n"
    ":10A52000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF3B\n"
    ":10A53000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF2B\n"
    ":10A54000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1B\n"
    ":10A55000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0B\n"
    ":10A56000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB\n"
    ":10A57000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB\n"
    ":10A58000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDB\n"
    ":10A59000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCB\n"
    ":10A5A000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBB\n"
    ":10A5B000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAB\n"
    ":10A5C000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF9B\n"
    ":10A5D000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8B\n"
    ":10A5E000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7B\n"
    ":10A5F000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6B\n"
    ":10A60000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5A\n"
    ":10A61000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF4A\n"
    ":10A62000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF3A\n"
    ":10A63000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF2A\n"
    ":10A64000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1A\n"
    ":10A65000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0A\n"
    ":10A66000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA\n"
    ":10A67000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEA\n"
    ":10A68000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDA\n"
    ":10A69000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCA\n"
    ":10A6A000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA\n"
    ":10A6B000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAA\n"
    ":10A6C000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF9A\n"
    ":10A6D000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8A\n"
    ":10A6E000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7A\n"
    ":10A6F000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6A\n"
    ":10A70000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF59\n"
    ":10A71000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF49\n"
    ":10A72000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF39\n"
    ":10A73000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF29\n"
    ":10A74000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF19\n"
    ":10A75000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF09\n"
    ":10A76000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF9\n"
    ":10A77000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9\n"
    ":10A78000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD9\n"
    ":10A79000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC9\n"
    ":10A7A000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB9\n"
    ":10A7B000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA9\n"
    ":10A7C000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF99\n"
    ":10A7D000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF89\n"
    ":10A7E000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF79\n"
    ":10A7F000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF69\n"
    # Application area end (0x0E1EB000)
    ":00000001FF\n"
)

expected_update_storage = (
    ":020000040E1ECE\n"
    ":10EC0000AA55AA55010000000000100EB60200002F\n"
    ":10EC100000000000000000000000000000000000F4\n"
    ":10EC200000000000000000000000000000000000E4\n"
    ":00000001FF\n"
)


expected_update_dfu_partition = (
    ":020000040E10DC\n"
    ":10000000D86BA4025827815824822F5820304548A5\n"
    ":100010007BD1B451ABF53601068E2381AF6EE36719\n"
    ":1000200029786E2E1289B21578B5CFEFFE0358DB12\n"
    ":10003000A801010201035870A202818444634D4566\n"
    ":100040004D4102451A0E0AA000451A000560000441\n"
    ":1000500058568614A401507617DAA571FD5A858F7B\n"
    ":1000600094E28D735CE9F4025008C1B59955E85FDC\n"
    ":10007000BC9E767BC29CE1B04D035824822F582051\n"
    ":100080005FC354BF8E8C50FB4FBC2CFAEB04534122\n"
    ":10009000C9806DEABDCB4154FB79CCA4F0C98C1268\n"
    ":1000A0000E190100010F020F074382030F0943825B\n"
    ":1000B000170211528614A115692366696C652E62B8\n"
    ":1000C000696E1502030F17822F5820592D8D0DF0E0\n"
    ":1000D00093D71D3682857255645E1B56403826487C\n"
    ":1000E000444604FFD56A20D84FE6DB05824C6B49B5\n"
    ":1000F0004E53544C445F4D4653545008C1B5995526\n"
    ":10010000E85FBC9E767BC29CE1B04D17589BA16214\n"
    ":10011000656EA18444634D454D4102451A0E0AA007\n"
    ":1001200000451A00056000A60178184E6F726469D8\n"
    ":10013000632053656D69636F6E647563746F7220BD\n"
    ":10014000415341026F6E524635344832305F63701E\n"
    ":1001500075617070036E6E6F7264696373656D694B\n"
    ":100160002E636F6D04781D546865206E52463534D9\n"
    ":10017000483230206170706C69636174696F6E2001\n"
    ":10018000636F726505781A53616D706C65206170DC\n"
    ":10019000706C69636174696F6E20636F726520466D\n"
    ":1001A00057066676312E302E30692366696C652ECF\n"
    ":1001B00062696E590100C79CAB9DE8337F3014EB38\n"
    ":1001C000AC02AF26015E806D88A1DB11A731DFA6EE\n"
    ":1001D000ECCB9B480DC834406D30867DE81BEC3C71\n"
    ":1001E000F540D0481882119D7C3F6CE58FF1D35DBE\n"
    ":1001F000E151F76A0FAF0BBD4C5FA5341A66DB22E5\n"
    ":10020000EC63ED4BABC7C8F759D8D69EEC711B24F5\n"
    ":1002100020B9AEE13BFCAEB877ACA4573497844F1D\n"
    ":1002200058D568086FE39C7E1BD738229848F87A27\n"
    ":1002300067B2D9ACC534C127828E42798421374C4C\n"
    ":10024000414A0FE27FA06A19133D52227FD62F71D7\n"
    ":100250001276AB259CFC6708037CDB18E645F89911\n"
    ":10026000C29E2CE39B25A97B09FF005726080A1193\n"
    ":1002700042CF82A26B2A99F9719D14195C5C783186\n"
    ":1002800060424A181FEC786A9A7C4FCFE85A296579\n"
    ":10029000CD013B6D53BBC6DBDAD58FF7F4D9B90A74\n"
    ":1002A000034BFF33AB3BC5AFD0B82C0F6AA911B0DD\n"
    ":0602B000E8578C92538117\n"
    ":00000001FF\n"
)

MPI_KCONFIG_TEMPLATE = """
CONFIG_SUIT_MPI_ROOT_VENDOR_NAME="{root_vendor_name}"
CONFIG_SUIT_MPI_ROOT_CLASS_NAME="{root_class_name}"
CONFIG_SUIT_MPI_APP_LOCAL_1=y
CONFIG_SUIT_MPI_APP_LOCAL_1_VENDOR_NAME="{app_local_1_vendor_name}"
CONFIG_SUIT_MPI_APP_LOCAL_1_CLASS_NAME="{app_local_1_class_name}"
CONFIG_SUIT_MPI_APP_LOCAL_2 is not set
CONFIG_SUIT_MPI_APP_LOCAL_3 is not set
CONFIG_SUIT_MPI_RAD_RECOVERY is not set
CONFIG_SUIT_MPI_RAD_LOCAL_1=y
CONFIG_SUIT_MPI_RAD_LOCAL_1_VENDOR_NAME="{rad_local_1_vendor_name}"
CONFIG_SUIT_MPI_RAD_LOCAL_1_CLASS_NAME="{rad_local_1_class_name}"
CONFIG_SUIT_MPI_RAD_LOCAL_2 is not set
"""

INPUT_ENVELOPE_YAML = """SUIT_Envelope_Tagged:
  suit-authentication-wrapper:
    SuitDigest:
      suit-digest-algorithm-id: cose-alg-sha-256
      suit-digest-bytes: abe742c95d30b5d0dcc33e03cc939e563b41673cd9c6d0c6d06a5300c9af182e
  suit-manifest:
    suit-manifest-version: 1
    suit-manifest-sequence-number: 1
    suit-common:
      suit-components:
      - - TEST
        - 1
        - 2
        - 3
    suit-manifest-component-id:
    - INSTLD_MFST
    - RFC4122_UUID:
        namespace: {component_id_namespace}
        name: {component_id_name}
"""


@pytest.fixture
def setup_and_teardown(tmp_path_factory):
    """Create and cleanup environment."""
    # Setup environment
    #   - create temp directory
    #   - input files
    start_directory = os.getcwd()
    path = tmp_path_factory.mktemp(TEMP_DIRECTORY)
    os.chdir(path)
    with open(".config", "w") as fh:
        fh.write(
            MPI_KCONFIG_TEMPLATE.format(
                root_vendor_name="root_custom_vendor",
                root_class_name="root_custom_class",
                app_local_1_vendor_name="app_local_1_custom_vendor",
                app_local_1_class_name="app_local_1_custom_class",
                rad_local_1_vendor_name="rad_local_1_custom_vendor",
                rad_local_1_class_name="rad_local_1_custom_class",
            )
        )
    for item_name in ["root", "app_local_1", "rad_local_1"]:
        with open(f"custom_{item_name}_component_id.suit", "wb") as fh:
            envelope_data = SuitEnvelopeTagged.from_obj(
                yaml.load(
                    INPUT_ENVELOPE_YAML.format(
                        component_id_namespace=f"{item_name}_custom_vendor",
                        component_id_name=f"{item_name}_custom_class",
                    ),
                    Loader=yaml.FullLoader,
                )
            ).to_cbor()
            fh.write(envelope_data)
    yield
    # Cleanup environment
    #   - remove temp directory
    os.chdir(start_directory)


def prepare_calls(data):
    """Split data by lines and wrap each line using _Call object for easy assertions; get rid of last newline"""
    return [_Call(("", (f"{line}\n",))) for line in data.split("\n")[:-1]]


@pytest.mark.parametrize("nb_of_caches", range(MAX_CACHE_COUNT + 1))
def test_struct_format(nb_of_caches):
    caches_format = "II" * nb_of_caches
    format = "<IIII" + caches_format
    assert ImageCreator._prepare_suit_storage_struct_format(nb_of_caches) == format


def test_update_candidate_info_verify_class_id_offset():
    from suit_generator.envelope import SuitEnvelope
    from suit_generator.suit.envelope import SuitEnvelopeTagged
    from cbor2 import loads as cbor_loads

    # Generate envlope object
    envelope = SuitEnvelope()
    envelope._envelope = SuitEnvelopeTagged.from_cbor(signed_envelope_input).to_obj()

    # Generate storage envelope slot for the envelope
    storage = EnvelopeStorageNrf54h20(0)
    storage.add_envelope(envelope)
    (envelope_role, envelope_cbor) = storage._envelopes.popitem()

    # Extract the class ID, based on the offset and minified envelope
    storage_dict = cbor_loads(envelope_cbor)
    offset = storage_dict[EnvelopeStorageNrf54h20.ENVELOPE_SLOT_CLASS_ID_OFFSET_KEY]
    envelope_bstr = storage_dict[EnvelopeStorageNrf54h20.ENVELOPE_SLOT_ENVELOPE_BSTR_KEY]

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
            storage_address=0,
            dfu_partition_output_file="",
            dfu_partition_address=0,
            dfu_max_caches=0,
        )


def test_boot_subcommand_nonexisting_input_file():
    with pytest.raises(GeneratorError):
        cmd_image_main(
            image="boot",
            input_file=["nonexisting"],
            storage_output_directory="",
            update_candidate_info_address=0,
            storage_address=0,
            envelope_slot_size=2048,
            envelope_slot_count=8,
            dfu_partition_output_file="",
            dfu_partition_address=0,
            dfu_max_caches=0,
            config_file=None,
        )


def test_boot_subcommand_manifest_without_component_id(mocker):
    io_mock = mocker.mock_open(read_data=signed_envelope_without_class_id_input)
    mocker.patch("builtins.open", io_mock)

    with pytest.raises(GeneratorError):
        cmd_image_main(
            image="boot",
            input_file=["some_input"],
            storage_output_directory="some_output",
            update_candidate_info_address=0x0E1EEC00,
            storage_address=0x0E1EED80,
            envelope_slot_size=2048,
            envelope_slot_count=8,
            dfu_partition_output_file="",
            dfu_partition_address=0,
            dfu_max_caches=4,
            config_file=None,
        )


def test_boot_subcommand_success(mocker):
    io_mock = mocker.mock_open(read_data=signed_envelope_input)
    mocker.patch("builtins.open", io_mock)

    cmd_image_main(
        image="boot",
        input_file=["some_input"],
        storage_output_directory="some_output",
        update_candidate_info_address=0x0E1E9340,
        storage_address=0x0E1E7000,
        envelope_slot_size=2048,
        envelope_slot_count=1,
        dfu_partition_output_file="",
        dfu_partition_address=0,
        dfu_max_caches=6,
        config_file=None,
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
            storage_address=0,
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
        storage_address=0x0E1EED80,
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
            input_file=["some_input"],
            storage_output_directory="some_output",
            update_candidate_info_address=0x0E1FE000,
            storage_address=0x0E1FF000,
            envelope_slot_size=2048,
            envelope_slot_count=8,
            dfu_partition_output_file="",
            dfu_partition_address=0,
            dfu_max_caches=0,
            config_file=None,
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
            storage_address=0x0E1EED80,
            dfu_partition_output_file="some_dfu_partition_output",
            dfu_partition_address=0x0E100000,
            dfu_max_caches=4,
        )


def test_nrf54_storage_no_defaults():
    storage = EnvelopeStorageNrf54h20(base_address=0xFF, load_defaults=False, kconfig=None)
    assert storage._assignments == []


def test_nrf54_storage_defaults():
    storage = EnvelopeStorageNrf54h20(base_address=0xFF, load_defaults=True, kconfig=None)
    assert len(storage._assignments) == 8


def test_nrf54_storage_custom_config_defaults(setup_and_teardown):
    storage = EnvelopeStorageNrf54h20(base_address=0xFF, load_defaults=True, kconfig=".config")
    assert len(storage._assignments) == 11


def test_nrf54_storage_custom_config_no_defaults(setup_and_teardown):
    storage = EnvelopeStorageNrf54h20(base_address=0xFF, load_defaults=False, kconfig=".config")
    assert len(storage._assignments) == 3


def test_generate_boot_images_for_default_vid_cid():
    pass


@pytest.mark.parametrize(
    "input_envelope, expected_storage",
    [
        ("custom_app_local_1_component_id.suit", "suit_installed_envelopes_application_merged.hex"),
        ("custom_rad_local_1_component_id.suit", "suit_installed_envelopes_radio_merged.hex"),
        ("custom_root_component_id.suit", "suit_installed_envelopes_application_merged.hex"),
    ],
)
def test_generate_boot_images_for_custom_vid_cid_separately(setup_and_teardown, input_envelope, expected_storage):
    """Test generating boot images for custom VID/CID separately."""
    ImageCreator.create_files_for_boot(
        input_files=[input_envelope],
        storage_output_directory="./",
        storage_address=0,
        config_file=".config",
    )
    assert pathlib.Path(expected_storage).is_file()


def test_generate_boot_images_for_custom_vid_cid_all_envelopes_in_one_request(setup_and_teardown):
    """Test generating boot images for custom VID/CID in one request."""
    ImageCreator.create_files_for_boot(
        input_files=[
            "custom_app_local_1_component_id.suit",
            "custom_rad_local_1_component_id.suit",
            "custom_root_component_id.suit",
        ],
        storage_output_directory="./",
        storage_address=0,
        config_file=".config",
    )
    assert pathlib.Path("suit_installed_envelopes_application_merged.hex").is_file()
    assert pathlib.Path("suit_installed_envelopes_radio_merged.hex").is_file()


def test_generate_update_images_for_custom_non_defined_vid_cid(setup_and_teardown):
    """Test generating update images for custom VID/CID when VID/CID is not known."""
    with pytest.raises(GeneratorError):
        ImageCreator.create_files_for_boot(
            input_files=[
                "custom_app_local_1_component_id.suit",
                "custom_rad_local_1_component_id.suit",
                "custom_root_component_id.suit",
            ],
            storage_output_directory="./",
            storage_address=0,
            config_file=None,
        )
