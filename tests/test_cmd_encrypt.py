# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for cmd_encrypt.py implementation."""

import pytest
import os
import pathlib
import encrypt_script_mock
import json

from suit_generator.cmd_encrypt import main as cmd_encrypt_main


TEMP_DIRECTORY = pathlib.Path("test_test_data")


@pytest.fixture
def setup_and_teardown(tmp_path_factory):
    """Create and cleanup environment."""
    # Setup environment
    #   - create required files in TEMP_DIRECTORY
    start_directory = os.getcwd()
    path = tmp_path_factory.mktemp(TEMP_DIRECTORY)
    os.chdir(path)
    yield
    # Cleanup environment
    #   - remove temp directory
    os.chdir(start_directory)


@pytest.mark.parametrize(
    "firmware, key_name, key_id, hash_alg, kw_alg, ctx, kms_script, encrypted_data, "
    + "tag, encryption_info, digest, plaintext_length, output_dir_name",
    [
        (
            b"test_firmware",
            "test_key",
            0x40000000,
            "sha-256",
            "direct",
            "test_ctx",
            "test_kms_script.py",
            b"test_encrypted_data",
            b"test_tag",
            b"test_encryption_info",
            b"test_digest",
            123,
            "enc_artifacts1",
        ),
        (
            b"firmware2",
            "key2",
            0x12345678,
            "sha-512",
            "aes-kw-256",
            "testctx2",
            "kms_script2.py",
            b"encrypted_data2",
            b"tag2",
            b"encryption_info2",
            b"digest2",
            5000,
            "enc_artifacts2",
        ),
    ],
)
def test_encrypt_cmd_encrypt_and_generate(
    setup_and_teardown,
    firmware,
    key_name,
    key_id,
    hash_alg,
    kw_alg,
    ctx,
    kms_script,
    encrypted_data,
    tag,
    encryption_info,
    digest,
    plaintext_length,
    output_dir_name,
):
    """Test the encrypt-and-generate command"""

    full_context = json.dumps(
        {
            "ctx": ctx,
            "encrypted_data": encrypted_data.hex(),
            "tag": tag.hex(),
            "encryption_info": encryption_info.hex(),
            "digest": digest.hex(),
            "plaintext_length": plaintext_length,
        }
    )

    os.mkdir(output_dir_name)
    firmware_file_name = "fw.bin"
    with open(firmware_file_name, "wb") as file:
        file.write(firmware)

    kwargs = {
        "encrypt_subcommand": "encrypt-and-generate",
        "firmware": firmware_file_name,
        "key_name": key_name,
        "key_id": key_id,
        "hash_alg": hash_alg,
        "kw_alg": kw_alg,
        "context": full_context,
        "output_dir": output_dir_name,
        "kms_script": kms_script,
        "encrypt_script": str(encrypt_script_mock.__file__),
    }

    cmd_encrypt_main(**kwargs)

    assert os.path.exists(f"test_output_{key_name}.json")
    assert os.path.exists(output_dir_name)
    assert os.path.exists(f"{output_dir_name}/plain_text_digest.bin")
    assert os.path.exists(f"{output_dir_name}/plain_text_size.txt")
    assert os.path.exists(f"{output_dir_name}/suit_encryption_info.bin")
    assert os.path.exists(f"{output_dir_name}/encrypted_content.bin")

    test_json_data = json.load(open(f"test_output_{key_name}.json"))

    assert test_json_data["firmware"] == firmware.hex()
    assert test_json_data["key_name"] == key_name
    assert test_json_data["key_id"] == key_id
    assert test_json_data["kw_alg"] == kw_alg
    assert test_json_data["hash_alg"] == hash_alg
    assert test_json_data["context"] == ctx
    assert test_json_data["kms_script"] == kms_script

    assert open(f"{output_dir_name}/plain_text_digest.bin", "rb").read() == digest
    assert open(f"{output_dir_name}/plain_text_size.txt", "r").read() == str(plaintext_length)
    assert open(f"{output_dir_name}/suit_encryption_info.bin", "rb").read() == encryption_info
    assert open(f"{output_dir_name}/encrypted_content.bin", "rb").read() == tag + encrypted_data


@pytest.mark.parametrize(
    "encrypted_firmware, encrypted_key, key_id, kw_alg, encrypted_data, tag, encryption_info, output_dir_name",
    [
        (
            b"test_encrypted_firmware",
            b"test_encrypted_key",
            0x40000000,
            "direct",
            b"test_encrypted_data",
            b"test_tag",
            b"test_encryption_info",
            "gen_artifacts1",
        ),
        (
            b"encrypted_firmware2",
            b"encrypted_key2",
            0x12345678,
            "aes-kw-256",
            b"encrypted_data2",
            b"tag2",
            b"encryption_info2",
            "gen_artifacts2",
        ),
    ],
)
def test_encrypt_cmd_generate(
    setup_and_teardown,
    encrypted_firmware,
    encrypted_key,
    key_id,
    kw_alg,
    encrypted_data,
    tag,
    encryption_info,
    output_dir_name,
):
    """Test the generate-info command"""

    os.mkdir(output_dir_name)
    encrypted_firmware_file_name = "encrypted_fw.bin"
    encrypted_key_file_name = "encrypted_key.bin"

    context = json.dumps(
        {
            "encrypted_data": encrypted_data.hex(),
            "tag": tag.hex(),
            "encryption_info": encryption_info.hex(),
        }
    )

    with open(encrypted_firmware_file_name, "wb") as file:
        file.write(context.encode())
    with open(encrypted_key_file_name, "wb") as file:
        file.write(encrypted_key)

    kwargs = {
        "encrypt_subcommand": "generate-info",
        "encrypted_firmware": encrypted_firmware_file_name,
        "encrypted_key": encrypted_key_file_name,
        "key_id": key_id,
        "kw_alg": kw_alg,
        "output_dir": output_dir_name,
        "encrypt_script": str(encrypt_script_mock.__file__),
    }

    cmd_encrypt_main(**kwargs)

    assert os.path.exists(f"test_output_{key_id}.json")
    assert os.path.exists(output_dir_name)
    assert os.path.exists(f"{output_dir_name}/suit_encryption_info.bin")
    assert os.path.exists(f"{output_dir_name}/encrypted_content.bin")

    test_json_data = json.load(open(f"test_output_{key_id}.json"))

    assert test_json_data["key_id"] == key_id
    assert test_json_data["kw_alg"] == kw_alg
    assert test_json_data["encrypted_cek"] == encrypted_key.hex()

    assert open(f"{output_dir_name}/suit_encryption_info.bin", "rb").read() == encryption_info
    assert open(f"{output_dir_name}/encrypted_content.bin", "rb").read() == tag + encrypted_data
