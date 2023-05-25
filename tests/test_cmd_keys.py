#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for cmd_keys.py implementation."""

import os
import pytest

from suit_generator.cmd_keys import KeyGenerator
from suit_generator.exceptions import GeneratorError


all_key_types = ("secp256r1", "secp384r1", "secp521r1", "ed25519", "ed448")
all_encodings = ("pem", "der")
all_private_formats = ("pkcs1", "pkcs8")
all_public_formats = ("default", "pkcs1")
all_encryptions = ("none",)


@pytest.fixture(scope="session")
def keys_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("keys")


@pytest.fixture
def key_generator():
    return KeyGenerator()


def test_object_creation(key_generator):
    """Test if KeyGenerator instance can be created"""
    assert key_generator


@pytest.mark.parametrize("key_type", all_key_types)
@pytest.mark.parametrize("encoding", all_encodings)
@pytest.mark.parametrize("private_format", ("pkcs8",))
@pytest.mark.parametrize("public_format", ("default",))
@pytest.mark.parametrize("encryption", all_encryptions)
def test_valid_parameters(key_generator, keys_dir, key_type, encoding, private_format, public_format, encryption):
    """Private and public key formats 'pkcs8' and 'default' respectively should work with all remaining parameters"""
    file_prefix = f"{keys_dir}/{key_type}"
    expected_private_file = f"{file_prefix}_priv.{encoding}"
    expected_public_file = f"{file_prefix}_pub.{encoding}"

    try:
        key_generator.create_key_pair(file_prefix, key_type, encoding, private_format, public_format, encryption)
    except Exception as error:
        assert False, f"{error}"

    assert os.stat(expected_private_file).st_size > 0
    assert os.stat(expected_public_file).st_size > 0


@pytest.mark.parametrize("key_type", ("ed25519", "ed448"))
@pytest.mark.parametrize("encoding", all_encodings)
@pytest.mark.parametrize("private_format", ("pkcs1",))
@pytest.mark.parametrize("public_format", all_public_formats)
@pytest.mark.parametrize("encryption", all_encryptions)
def test_invalid_private_format_parameters_combination(
    key_generator, keys_dir, key_type, encoding, private_format, public_format, encryption
):
    """Private format 'pkcs1' is not supported for 'ed*' curves"""
    file_prefix = f"{keys_dir}/{key_type}"
    with pytest.raises(GeneratorError):
        key_generator.create_key_pair(file_prefix, key_type, encoding, private_format, public_format, encryption)


@pytest.mark.parametrize("key_type", all_key_types)
@pytest.mark.parametrize("encoding", all_encodings)
@pytest.mark.parametrize("private_format", ("pkcs8",))
@pytest.mark.parametrize("public_format", ("default",))
@pytest.mark.parametrize("encryption", all_encryptions)
def test_wrong_path(key_generator, key_type, encoding, private_format, public_format, encryption):
    """Invalid file path should result with exception"""
    with pytest.raises(GeneratorError):
        key_generator.create_key_pair(
            "/tmp/nonexisting/file", key_type, encoding, private_format, public_format, encryption
        )
