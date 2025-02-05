#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Generate encryption artifacts for SUIT."""

import uuid
import logging
import importlib.util
import sys
import os
from argparse import RawTextHelpFormatter
from pathlib import Path
from suit_generator.suit_encrypt_script_base import (
    SuitEncryptorBase,
    SuitDigestAlgorithms,
    SuitKWAlgorithms,
)
from suit_generator.exceptions import GeneratorError

ENCRYPT_AND_GENERATE_FIRMWARE_CMD = "encrypt-and-generate"
GENERATE_INFO_FIRMWARE_CMD = "generate-info"

log = logging.getLogger(__name__)

ENCRYPT_CMD = "encrypt"


def _import_module_from_path(module_name: str, file_path: Path):
    """Import a python module from a file path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _import_encryptor(encrypt_script: Path) -> SuitEncryptorBase:
    """Import an a encryptor object from the encrypt script."""
    module_name = "SuitEncryptScript_module" + uuid.uuid4().hex
    encryptor_module = _import_module_from_path(module_name, encrypt_script)
    if not hasattr(encryptor_module, "suit_encryptor_factory"):
        raise ValueError(f"Module {encrypt_script} does not contain a suit_encryptor_factory function.")
    encryptor = encryptor_module.suit_encryptor_factory()
    if not isinstance(encryptor, SuitEncryptorBase):
        raise ValueError(f"Class {type(encryptor)} does not implement the required SuitEnvelopeSignerBase interface")

    return encryptor


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_encrypt_arg_parser = parser.add_parser(
        ENCRYPT_CMD,
        help="Generate encryption artifacts for SUIT.",
        description="""This script allows to output artifacts needed by a SUIT envelope for encrypted firmware.

It has two modes of operation:
    - encrypt-and-generate: First encrypt the payload, then generate the files.
    - generate: Only generate files based on encrypted firmware and the encrypted content/asset encryption key.
    Note the encrypted firmware should match the format iv|tag|encrypted_firmware

In both cases the output files are:
    encrypted_content.bin - encrypted content of the firmware concatenated with the tag (encrypted firmware|16 byte tag).
                            This file is used as the payload in the SUIT envelope.
    suit_encryption_info.bin - The binary contents which should be included in the SUIT envelope as the contents of the suit-encryption-info parameter.

Additionally, the encrypt-and-generate mode generates the following file:
    plain_text_digest.bin - The digest of the plaintext firmware.
    plain_text_size.txt - The size of the plaintext firmware in bytes.
    """,  # noqa: W291, E501
        formatter_class=RawTextHelpFormatter,
    )

    cmd_encrypt_subparsers = cmd_encrypt_arg_parser.add_subparsers(
        dest="encrypt_subcommand", required=True, help="Choose encrypt subcommand"
    )

    cmd_encrypt_and_generate_parser = cmd_encrypt_subparsers.add_parser(
        ENCRYPT_AND_GENERATE_FIRMWARE_CMD, help="First encrypt the payload, then generate the files."
    )

    cmd_encrypt_and_generate_parser.add_argument(
        "--firmware", required=True, type=Path, help="Input, plaintext firmware."
    )
    cmd_encrypt_and_generate_parser.add_argument(
        "--key-name", required=True, type=str, help="Name of the key used by the KMS to identify the key."
    )
    cmd_encrypt_and_generate_parser.add_argument(
        "--key-id",
        required=True,
        type=lambda x: int(x, 0),
        help="Key ID used to identify the key on the device.",
    )
    cmd_encrypt_and_generate_parser.add_argument(
        "--context",
        type=str,
        help="Any context information that should be passed to the KMS backend during initialization and encryption.",
    )
    cmd_encrypt_and_generate_parser.add_argument(
        "--output-dir", required=True, type=Path, help="Directory to store the output files"
    )
    cmd_encrypt_and_generate_parser.add_argument(
        "--hash-alg",
        default=SuitDigestAlgorithms.SHA_256.value,
        type=SuitDigestAlgorithms,
        choices=list(SuitDigestAlgorithms),
        help="Algorithm used to create plaintext digest.",
    )
    cmd_encrypt_and_generate_parser.add_argument(
        "--kw-alg",
        default=SuitKWAlgorithms.DIRECT.value,
        type=SuitKWAlgorithms,
        choices=list(SuitKWAlgorithms),
        help="Key wrap algorithm used to wrap the CEK.",
    )
    cmd_encrypt_and_generate_parser.add_argument(
        "--kms-script",
        help="Python script containing a SuitKMS class with an encrypt function - used to communicate with a KMS.",
    )

    cmd_encrypt_and_generate_parser.add_argument(
        "--encrypt-script",
        required=True,
        help="Encrypt script used to generate the encryption artifacts. "
        + "It must contain a function suit_encryptor_factory() returning an object implementing SuitEncryptorBase.",
    )

    cmd_generate_info_parser = cmd_encrypt_subparsers.add_parser(
        GENERATE_INFO_FIRMWARE_CMD, help="Only generate artifacts based on encrypted firmware."
    )

    cmd_generate_info_parser.add_argument(
        "--encrypted-firmware",
        required=True,
        type=Path,
        help="Input, encrypted firmware in form iv|tag|encrypted_firmware",
    )
    cmd_generate_info_parser.add_argument(
        "--encrypted-key", required=True, type=Path, help="Encrypted content/asset encryption key"
    )
    cmd_generate_info_parser.add_argument(
        "--key-id",
        required=True,
        type=lambda x: int(x, 0),
        help="Key ID used to identify the key on the device.",
    )
    cmd_generate_info_parser.add_argument(
        "--kw-alg",
        default=SuitKWAlgorithms.DIRECT.value,
        type=SuitKWAlgorithms,
        choices=list(SuitKWAlgorithms),
        help="Key wrap algorithm used to wrap the CEK.",
    )
    cmd_generate_info_parser.add_argument(
        "--output-dir", required=True, type=Path, help="Directory to store the output files"
    )

    cmd_generate_info_parser.add_argument(
        "--encrypt-script",
        required=True,
        help="Encrypt script used to generate the encryption artifacts. "
        + "It must contain a function suit_encryptor_factory() returning an object implementing SuitEncryptorBase.",
    )


def encrypt_and_generate(**kwargs):
    """Encrypt the payload and generate the files."""
    encryptor = _import_encryptor(kwargs["encrypt_script"])
    with open(kwargs["firmware"], "rb") as file:
        plaintext = file.read()
    encrypted_content, tag, encryption_info, digest, plaintext_len = encryptor.encrypt_and_generate(
        plaintext,
        kwargs["key_name"],
        kwargs["key_id"],
        kwargs["context"],
        kwargs["hash_alg"],
        kwargs["kw_alg"],
        kwargs["kms_script"],
    )
    with open(os.path.join(kwargs["output_dir"], "plain_text_digest.bin"), "wb") as file:
        file.write(digest)
    with open(os.path.join(kwargs["output_dir"], "plain_text_size.txt"), "w") as file:
        file.write(str(plaintext_len))
    with open(os.path.join(kwargs["output_dir"], "suit_encryption_info.bin"), "wb") as file:
        file.write(encryption_info)
    with open(os.path.join(kwargs["output_dir"], "encrypted_content.bin"), "wb") as file:
        file.write(tag + encrypted_content)


def generate_info(**kwargs):
    """Generate files based on encrypted firmware and the encrypted content/asset encryption key."""
    encryptor = _import_encryptor(kwargs["encrypt_script"])
    with open(kwargs["encrypted_firmware"], "rb") as file:
        encrypted_firmware = file.read()
    with open(kwargs["encrypted_key"], "rb") as file:
        encrypted_key = file.read()
    encrypted_content, tag, encryption_info = encryptor.generate(
        encrypted_firmware,
        encrypted_key,
        kwargs["key_id"],
        kwargs["kw_alg"],
    )
    with open(os.path.join(kwargs["output_dir"], "suit_encryption_info.bin"), "wb") as file:
        file.write(encryption_info)
    with open(os.path.join(kwargs["output_dir"], "encrypted_content.bin"), "wb") as file:
        file.write(tag + encrypted_content)


def main(**kwargs) -> None:
    """Sign a SUIT envelope."""
    if kwargs["encrypt_subcommand"] == ENCRYPT_AND_GENERATE_FIRMWARE_CMD:
        encrypt_and_generate(**kwargs)
    elif kwargs["encrypt_subcommand"] == GENERATE_INFO_FIRMWARE_CMD:
        generate_info(**kwargs)
    else:
        raise GeneratorError(f"Invalid 'encrypt' subcommand: {kwargs['encrypt_subcommand']}")
