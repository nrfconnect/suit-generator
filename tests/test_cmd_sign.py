# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for cmd_sign.py implementation."""

import pytest
import sign_script_mock
import os
import pathlib
import binascii
import json
import cbor2
from suit_generator.cmd_sign import main as cmd_sign_main
from suit_generator.suit.envelope import SuitEnvelopeTagged
from suit_generator.suit.types.keys import (
    suit_authentication_wrapper,
)
from suit_generator.suit_sign_script_base import (
    SignatureAlreadyPresentActions,
    SuitSignAlgorithms,
)

UNSIGNED_ROOT_INPUT_ENVELOPE = (
    "d86ba4025827815824822f58205a80213233ef0b3058a960eb8308bf3ead4843"
    "d9525855723a5fa3e1a9120852034aa3010102011443820c006623726164696f"
    "5839d86ba2025827815824822f5820b5baa7206121462b530c7bf0b34d92d727"
    "407a3ea36d576c3bf29aa8a5dc1a47034aa3010102011443820c016c23617070"
    "6c69636174696f6e5839d86ba2025827815824822f5820b5baa7206121462b53"
    "0c7bf0b34d92d727407a3ea36d576c3bf29aa8a5dc1a47034aa3010102011443"
    "820c01"
)

TEST_ROOT_KEY_NAME = "MANIFEST_OEM_ROOT_GEN1_priv"
TEST_ROOT_KEY_ID = 0x4000AA00
TEST_ROOT_ALGORITHM = "eddsa"
TEST_ROOT_CONTEXT = "test_ctx"
TEST_ROOT_KMS_SCRIPT = "test_kms_script.py"
TEST_ROOT_ALREADY_SIGNED_ACTION = "error"
TEST_ROOT_MOCKED_SIGNATURE = "mocked_signature"

TEST_RADIO_KEY_NAME = "MANIFEST_RADIOCORE_GEN1_priv"
TEST_RADIO_KEY_ID = 0x40032100
TEST_RADIO_ALGORITHM = "hash-eddsa"
TEST_RADIO_CONTEXT = "test_ctx_radio"
TEST_RADIO_KMS_SCRIPT = "test_kms_script_radio.py"
TEST_RADIO_ALREADY_SIGNED_ACTION = "skip"
TEST_RADIO_MOCKED_SIGNATURE = "mocked_signature_radio"

TEST_APPLICATION_KEY_NAME = "MANIFEST_APPLICATION_GEN1_priv"
TEST_APPLICATION_KEY_ID = 0x40022100


JSON_CONFIG_SIGN_ALL = {
    "key-name": TEST_ROOT_KEY_NAME,
    "key-id": hex(TEST_ROOT_KEY_ID),
    "alg": TEST_ROOT_ALGORITHM,
    "context": f'{{"ctx": "{TEST_ROOT_CONTEXT}", "signature": "{TEST_ROOT_MOCKED_SIGNATURE}"}}',
    "sign-script": str(sign_script_mock.__file__),
    "kms-script": TEST_ROOT_KMS_SCRIPT,
    "omit-signing": False,
    "already-signed-action": TEST_ROOT_ALREADY_SIGNED_ACTION,
    "dependencies": {
        "#radio": {
            "key-name": TEST_RADIO_KEY_NAME,
            "key-id": hex(TEST_RADIO_KEY_ID),
            "alg": TEST_RADIO_ALGORITHM,
            "context": f'{{"ctx": "{TEST_RADIO_CONTEXT}", "signature": "{TEST_RADIO_MOCKED_SIGNATURE}"}}',
            "sign-script": str(sign_script_mock.__file__),
            "kms-script": TEST_RADIO_KMS_SCRIPT,
            "already-signed-action": TEST_RADIO_ALREADY_SIGNED_ACTION,
        },
        "#application": {
            "key-name": TEST_APPLICATION_KEY_NAME,
            "key-id": hex(TEST_APPLICATION_KEY_ID),
        },
    },
}

TEMP_DIRECTORY = pathlib.Path("test_test_data")


@pytest.fixture
def setup_and_teardown(tmp_path_factory):
    """Create and cleanup environment."""
    # Setup environment
    #   - create required files in TEMP_DIRECTORY
    start_directory = os.getcwd()
    path = tmp_path_factory.mktemp(TEMP_DIRECTORY)
    os.chdir(path)
    with open("test_envelope.suit", "wb") as fh:
        fh.write(binascii.a2b_hex(UNSIGNED_ROOT_INPUT_ENVELOPE))
    yield
    # Cleanup environment
    #   - remove temp directory
    os.chdir(start_directory)


@pytest.mark.parametrize(
    "key_name, key_id, algorithm, ctx, mocked_signature, kms_script, already_signed_action",
    [
        ("test_key", 0x40000000, "es-256", "test_ctx", "test_signature", "test_kms_script.py", "skip"),
        ("test_key2", 0x12345678, "eddsa", "test_ctx2", "test_signature2", "test_kms_script2.py", "remove-old"),
    ],
)
def test_single_level_sign(
    setup_and_teardown, key_name, key_id, algorithm, ctx, mocked_signature, kms_script, already_signed_action
):
    """Test the single level sign commands"""

    full_context = {"ctx": ctx, "signature": mocked_signature}

    kwargs = {
        "sign_subcommand": "single-level",
        "input_envelope": "test_envelope.suit",
        "key_name": key_name,
        "key_id": key_id,
        "alg": SuitSignAlgorithms(algorithm),
        "context": json.dumps(full_context),
        "kms_script": kms_script,
        "already_signed_action": SignatureAlreadyPresentActions(already_signed_action),
        "sign_script": sign_script_mock.__file__,
        "output_envelope": "test_envelope_out.suit",
    }

    cmd_sign_main(**kwargs)

    assert os.path.exists(f"test_output_{key_name}.json")
    assert os.path.exists("test_envelope_out.suit")

    test_json_data = json.load(open(f"test_output_{key_name}.json"))

    assert test_json_data["key_name"] == key_name
    assert test_json_data["key_id"] == key_id
    assert test_json_data["algorithm"] == algorithm
    assert test_json_data["context"] == ctx
    assert test_json_data["kms_script"] == kms_script
    assert test_json_data["already_signed_action"] == already_signed_action

    with open("test_envelope_out.suit", "rb") as fh:
        envelope_signed_cbor_tag = cbor2.load(fh)

    envelope = SuitEnvelopeTagged.from_cbor(cbor2.dumps(envelope_signed_cbor_tag))
    signature = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[3]
        .SuitHex
    )
    assert signature == mocked_signature.encode()


# Helper function to verify the root (top level) envelope after recursive signing
def verify_root_envelope(envelope_signed_cbor_tag):
    assert os.path.exists(f"test_output_{TEST_ROOT_KEY_NAME}.json")
    test_root_json_data = json.load(open(f"test_output_{TEST_ROOT_KEY_NAME}.json"))

    assert test_root_json_data["key_name"] == TEST_ROOT_KEY_NAME
    assert test_root_json_data["key_id"] == TEST_ROOT_KEY_ID
    assert test_root_json_data["algorithm"] == TEST_ROOT_ALGORITHM
    assert test_root_json_data["context"] == TEST_ROOT_CONTEXT
    assert test_root_json_data["kms_script"] == TEST_ROOT_KMS_SCRIPT
    assert test_root_json_data["already_signed_action"] == TEST_ROOT_ALREADY_SIGNED_ACTION

    envelope = SuitEnvelopeTagged.from_cbor(cbor2.dumps(envelope_signed_cbor_tag))
    root_signature = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[3]
        .SuitHex
    )
    assert root_signature == TEST_ROOT_MOCKED_SIGNATURE.encode()


# Helper function to verify the radio envelope after recursive signing
def verify_radio_envelope(radio_envelope_cbor_tag):
    assert os.path.exists(f"test_output_{TEST_RADIO_KEY_NAME}.json")
    test_radio_json_data = json.load(open(f"test_output_{TEST_RADIO_KEY_NAME}.json"))

    assert test_radio_json_data["key_name"] == TEST_RADIO_KEY_NAME
    assert test_radio_json_data["key_id"] == TEST_RADIO_KEY_ID
    assert test_radio_json_data["algorithm"] == TEST_RADIO_ALGORITHM
    assert test_radio_json_data["context"] == TEST_RADIO_CONTEXT
    assert test_radio_json_data["kms_script"] == TEST_RADIO_KMS_SCRIPT
    assert test_radio_json_data["already_signed_action"] == TEST_RADIO_ALREADY_SIGNED_ACTION

    radio_envelope = SuitEnvelopeTagged.from_cbor(cbor2.dumps(radio_envelope_cbor_tag))
    radio_signature = (
        radio_envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[3]
        .SuitHex
    )
    assert radio_signature == TEST_RADIO_MOCKED_SIGNATURE.encode()


# Helper function to verify the application envelope after recursive signing
def verify_application_envelope(application_envelope_cbor_tag):
    assert os.path.exists(f"test_output_{TEST_APPLICATION_KEY_NAME}.json")
    test_application_json_data = json.load(open(f"test_output_{TEST_APPLICATION_KEY_NAME}.json"))

    assert test_application_json_data["key_name"] == TEST_APPLICATION_KEY_NAME
    assert test_application_json_data["key_id"] == TEST_APPLICATION_KEY_ID
    assert test_application_json_data["algorithm"] == TEST_ROOT_ALGORITHM
    assert test_application_json_data["context"] == TEST_ROOT_CONTEXT
    assert test_application_json_data["kms_script"] == TEST_ROOT_KMS_SCRIPT
    assert test_application_json_data["already_signed_action"] == TEST_ROOT_ALREADY_SIGNED_ACTION

    application_envelope = SuitEnvelopeTagged.from_cbor(cbor2.dumps(application_envelope_cbor_tag))
    application_signature = (
        application_envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[3]
        .SuitHex
    )
    assert application_signature == TEST_ROOT_MOCKED_SIGNATURE.encode()


def test_sign_recursive_all_signed(setup_and_teardown):
    with open("test_config.json", "w") as fh:
        json.dump(JSON_CONFIG_SIGN_ALL, fh)

    kwargs = {
        "sign_subcommand": "recursive",
        "input_envelope": "test_envelope.suit",
        "configuration": "test_config.json",
        "output_envelope": "test_envelope_out.suit",
    }
    cmd_sign_main(**kwargs)

    assert os.path.exists("test_envelope_out.suit")

    with open("test_envelope_out.suit", "rb") as fh:
        envelope_signed_cbor_tag = cbor2.load(fh)

    # Check if the resulting values for the root envelope are correct
    verify_root_envelope(envelope_signed_cbor_tag)

    # Check if the configuration for the radio envelope overrides the root configuration
    radio_envelope_cbor_tag = cbor2.loads(envelope_signed_cbor_tag.value["#radio"])
    verify_radio_envelope(radio_envelope_cbor_tag)

    # Check if the configuration for the application envelope inherits the root configuration
    application_envelope_cbor_tag = cbor2.loads(envelope_signed_cbor_tag.value["#application"])
    verify_application_envelope(application_envelope_cbor_tag)


def test_sign_recursive_omit_root(setup_and_teardown):
    omit_root_config = JSON_CONFIG_SIGN_ALL.copy()
    omit_root_config["omit-signing"] = True

    with open("test_config.json", "w") as fh:
        json.dump(omit_root_config, fh)

    kwargs = {
        "sign_subcommand": "recursive",
        "input_envelope": "test_envelope.suit",
        "configuration": "test_config.json",
        "output_envelope": "test_envelope_out.suit",
    }
    cmd_sign_main(**kwargs)

    assert os.path.exists("test_envelope_out.suit")
    assert not os.path.exists(f"test_output_{TEST_ROOT_KEY_NAME}.json")

    with open("test_envelope_out.suit", "rb") as fh:
        envelope_signed_cbor_tag = cbor2.load(fh)

    # Check if the configuration for the radio envelope overrides the root configuration
    radio_envelope_cbor_tag = cbor2.loads(envelope_signed_cbor_tag.value["#radio"])
    verify_radio_envelope(radio_envelope_cbor_tag)

    # Check if the configuration for the application envelope inherits the root configuration
    application_envelope_cbor_tag = cbor2.loads(envelope_signed_cbor_tag.value["#application"])
    verify_application_envelope(application_envelope_cbor_tag)


def test_sign_recursive_dependency_not_present(setup_and_teardown):
    no_radio_config = JSON_CONFIG_SIGN_ALL.copy()
    no_radio_config["dependencies"].pop("#radio")

    with open("test_config.json", "w") as fh:
        json.dump(no_radio_config, fh)
    kwargs = {
        "sign_subcommand": "recursive",
        "input_envelope": "test_envelope.suit",
        "configuration": "test_config.json",
        "output_envelope": "test_envelope_out.suit",
    }
    cmd_sign_main(**kwargs)

    assert os.path.exists("test_envelope_out.suit")
    assert not os.path.exists(f"test_output_{TEST_RADIO_KEY_NAME}.json")

    with open("test_envelope_out.suit", "rb") as fh:
        envelope_signed_cbor_tag = cbor2.load(fh)

    # Check if the resulting values for the root envelope are correct
    verify_root_envelope(envelope_signed_cbor_tag)

    # Check if the configuration for the application envelope inherits the root configuration
    application_envelope_cbor_tag = cbor2.loads(envelope_signed_cbor_tag.value["#application"])
    verify_application_envelope(application_envelope_cbor_tag)
