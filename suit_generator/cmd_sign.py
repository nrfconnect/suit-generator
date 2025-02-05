#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""CMD_SIGN CLI command entry point."""

import json
import uuid
import logging
import cbor2
import importlib.util
import sys
import os
from pathlib import Path
from suit_generator.suit_sign_script_base import (
    SuitEnvelopeSignerBase,
    SignatureAlreadyPresentActions,
    SuitSignAlgorithms,
)
from suit_generator.exceptions import GeneratorError
from argparse import RawTextHelpFormatter

SIGN_SINGLE_LEVEL_CMD = "single-level"
SIGN_RECURSIVE_CMD = "recursive"

log = logging.getLogger(__name__)

SIGN_CMD = "sign"


def _import_module_from_path(module_name: str, file_path: Path):
    """Import a python module from a file path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _import_signer(sign_script: Path) -> SuitEnvelopeSignerBase:
    """Import a signer object from the sign script."""
    module_name = "SuitSignScript_module" + uuid.uuid4().hex
    signer_module = _import_module_from_path(module_name, sign_script)
    if not hasattr(signer_module, "suit_signer_factory"):
        raise ValueError(f"Module {sign_script} does not contain a suit_signer_factory function.")
    signer = signer_module.suit_signer_factory()
    if not isinstance(signer, SuitEnvelopeSignerBase):
        raise ValueError(f"Class {type(signer)} does not implement the required SuitEnvelopeSignerBase interface")

    return signer


class RecursiveSigner:
    """Recursively sings a SUIT envelope."""

    def __init__(
        self,
        envelope: cbor2.CBORTag,
        envelope_json: dict,
        envelope_name: str,
        sign_script: Path = None,
        kms_script: Path = None,
        algorithm: SuitSignAlgorithms = SuitSignAlgorithms.EdDSA,
        context: str = None,
    ):
        """Initialize the RecursiveSigner."""
        self.envelope = envelope
        self.envelope_name = envelope_name
        self.sign_script = sign_script
        self.kms_script = kms_script
        self.alg = algorithm
        self.context = context
        self.dependencies = []
        self.omit_signing = False
        self.already_signed_action = SignatureAlreadyPresentActions.ERROR
        if "omit-signing" in envelope_json:
            self.omit_signing = envelope_json["omit-signing"]
        if "key-name" not in envelope_json and not self.omit_signing:
            raise ValueError(
                f"key-name not found in {envelope_name}, but signing is required (omit-signing is not set)."
            )
        self.key_name = envelope_json["key-name"]

        if "key-id" not in envelope_json and not self.omit_signing:
            raise ValueError(f"key-id not found in {envelope_name}, but signing is required (omit-signing is not set).")
        self.key_id = int(envelope_json["key-id"], 0)

        if "sign-script" in envelope_json:
            self.sign_script = envelope_json["sign_script"]
        elif self.sign_script is None:
            if os.environ.get("NCS_SUIT_SIGN_SCRIPT"):
                self.sign_script = os.environ.get("NCS_SUIT_SIGN_SCRIPT")
            elif os.environ.get("ZEPHYR_BASE"):
                self.sign_script = os.environ.get("ZEPHYR_BASE") + "/../modules/lib/suit-generator/ncs/sign_script.py"
            else:
                raise ValueError(
                    "sign-script not defined in the configuration and "
                    + "NCS_SUIT_SIGN_SCRIPT nor ZEPHYR_BASE are not set in the environment. "
                    + "Cannot set the sign script."
                )
        self.signer = _import_signer(self.sign_script)

        if "kms-script" in envelope_json:
            self.kms_script = envelope_json["kms_script"]
        elif self.kms_script is None:
            if os.environ.get("NCS_SUIT_KMS_SCRIPT"):
                self.kms_script = os.environ.get("NCS_SUIT_KMS_SCRIPT")
            elif os.environ.get("ZEPHYR_BASE"):
                self.kms_script = os.environ.get("ZEPHYR_BASE") + "/../modules/lib/suit-generator/ncs/basic_kms.py"
            else:
                raise ValueError(
                    "kms-script not defined in the configuration and"
                    + "NCS_SUIT_KMS_SCRIPT nor ZEPHYR_BASE are not set in the environment."
                    + "Cannot set the KMS script."
                )

        if "alg" in envelope_json:
            self.alg = SuitSignAlgorithms(envelope_json["alg"])
        if "context" in envelope_json:
            self.context = envelope_json["context"]
        if "already-signed-action" in envelope_json:
            self.already_signed_action = SignatureAlreadyPresentActions(envelope_json["already-signed-action"])

        if "dependencies" in envelope_json:
            if not isinstance(envelope_json["dependencies"], dict):
                raise ValueError(f"dependencies in {envelope_name} is not a dictionary.")
            for dep in envelope_json["dependencies"]:
                self.dependencies.append(
                    RecursiveSigner(
                        self._load_dependency(dep),
                        envelope_json["dependencies"][dep],
                        dep,
                        self.sign_script,
                        self.kms_script,
                        self.alg,
                        self.context,
                    )
                )

    def _load_dependency(self, dependency_name: str) -> cbor2.CBORTag:
        """Load the dependency from the envelope."""
        if dependency_name not in self.envelope.value:
            raise ValueError(f"Dependency {dependency_name} not found in {self.envelope_name}.")
        if not isinstance(self.envelope.value[dependency_name], bytes):
            raise ValueError(f"Dependency {dependency_name} in {self.envelope_name} is invalid.")
        try:
            dependency_envelope = cbor2.loads(self.envelope.value[dependency_name])
        except cbor2.CBORDecodeError:
            raise ValueError(f"Failed decoding dependency {dependency_name} in {self.envelope_name}")
        if not isinstance(dependency_envelope, cbor2.CBORTag):
            raise ValueError(f"Dependency {dependency_name} in {self.envelope_name} is not a valid envelope.")

        return dependency_envelope

    def _sign(self):
        self.envelope = self.signer.sign_envelope(
            self.envelope,
            self.key_name,
            self.key_id,
            self.alg,
            self.context,
            self.kms_script,
            self.already_signed_action,
        )

    def recursive_sign(self) -> cbor2.CBORTag:
        """Recursively sign the envelope and the dependencies."""
        for dep in self.dependencies:
            self.envelope.value[dep.envelope_name] = cbor2.dumps(dep.recursive_sign())
        if not self.omit_signing:
            self._sign()
        return self.envelope


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_sign_arg_parser = parser.add_parser(SIGN_CMD, help="Sign a SUIT envelope.")

    cmd_sign_subparsers = cmd_sign_arg_parser.add_subparsers(
        dest="sign_subcommand", required=True, help="Choose sign subcommand"
    )

    cmd_sign_single_level = cmd_sign_subparsers.add_parser(
        SIGN_SINGLE_LEVEL_CMD,
        help="Sign a single envelope - one level signing",
    )
    cmd_sign_single_level.add_argument("--input-envelope", required=True, type=Path, help="Input envelope.")
    cmd_sign_single_level.add_argument("--output-envelope", required=True, type=Path, help="Output envelope.")
    cmd_sign_single_level.add_argument(
        "--key-name", required=True, type=str, help="Name of the key used by the KMS to identify the key."
    )
    cmd_sign_single_level.add_argument(
        "--key-id",
        required=True,
        type=lambda x: int(x, 0),
        help="The key ID used to identify the key on the device",
    )
    cmd_sign_single_level.add_argument(
        "--alg",
        type=SuitSignAlgorithms,
        choices=list(SuitSignAlgorithms),
        default=SuitSignAlgorithms.ES_256,
        help="Algorithm used to sign the envelope.",
    )
    cmd_sign_single_level.add_argument(
        "--context",
        type=str,
        help="Any context information that should be passed to the KMS backend during initialization and signing.",
    )
    cmd_sign_single_level.add_argument(
        "--sign-script",
        required=True,
        help="Sign script used to attach a signature to the envelope. "
        + "It must contain a function suit_signer_factory() returning an object implementing SuitEnvelopeSignerBase.",
    )
    cmd_sign_single_level.add_argument(
        "--kms-script",
        required=True,
        help="Python script containing a SuitKMS class with an sign function - used to communicate with a KMS.",
    )
    cmd_sign_single_level.add_argument(
        "--already-signed-action",
        type=SignatureAlreadyPresentActions,
        choices=list(SignatureAlreadyPresentActions),
        default=SignatureAlreadyPresentActions.ERROR,
        help="Action to take when a signature is already present in the envelope.",
    )

    cmd_sign_recursive = cmd_sign_subparsers.add_parser(
        SIGN_RECURSIVE_CMD,
        help="Recursively sign the top level envelope and the integrated dependency envelopes.",
        description="""Recursively sign the top level envelope and the integrated dependency envelopes.

This command signs or omits signing of the top level envelope
and the integrated dependecy envelopes based on the provided configuration JSON file.

The configuration is a JSON dictionary with the following available attributes (most of them are optional):
    "sign-script" - path to the script used for signing a single envelope (default: sign_script.py)
    "kms-script" - path to the KMS script used by the sign-script (default: basic_kms.py)
    "alg" - algorithm used for signing (default: ed25519)
    "context" - context used by the KMS script (default: None)
    "key-name" - name of the key used for signing (required if omit-signing is not set)
    "key-id" - key ID of the public key used to identify the key on the device (required if omit-signing is not set)
    "already-signed-action" - action to be taken if the envelope is already signed (default: error)
                              Possible values: "error", "skip", "remove-old"
    "omit-signing" - boolean value indicating whether the envelope should be signed or not.
                     By default the envelope is signed (omit-signing set to false).
                     Note, that even if set to true the dependencies will still be parsed and optionally signed.
    "dependencies" - dictionary containing the integrated dependency envelope.
                    The keys are the names matching the names of the integrated dependencies in the parent envelope.
                    The values are the configuration dictionaries - all the mentioned attributes are avalable
                    inside these dictionaries.

    For reference see the suit-generator/ncs/sample_recursive_sign_config.json file
    """,  # noqa: W291, E501
        formatter_class=RawTextHelpFormatter,
    )
    cmd_sign_recursive.add_argument("--input-envelope", required=True, type=Path, help="Input envelope.")
    cmd_sign_recursive.add_argument("--output-envelope", required=True, type=Path, help="Output envelope.")
    cmd_sign_recursive.add_argument("--configuration", required=True, type=Path, help="A .json configuration file")


def load_envelope(input_file: Path) -> cbor2.CBORTag:
    """Load suit envelope."""
    with open(input_file, "rb") as fh:
        envelope = cbor2.load(fh)
    return envelope


def save_envelope(output_file: Path, envelope) -> None:
    """Store envelope."""
    with open(output_file, "wb") as fh:
        cbor2.dump(envelope, fh)


def single_level_sign(envelope, **kwargs) -> cbor2.CBORTag:
    """Sign a single envelope, without parsing it recursivelu."""
    signer = _import_signer(kwargs["sign_script"])
    envelope = signer.sign_envelope(
        envelope,
        kwargs["key_name"],
        kwargs["key_id"],
        kwargs["alg"],
        kwargs["context"],
        kwargs["kms_script"],
        kwargs["already_signed_action"],
    )
    return envelope


def recursive_sign(envelope, **kwargs) -> cbor2.CBORTag:
    """Sign a SUIT envelope recursively."""
    try:
        with open(kwargs["configuration"], "r") as fh:
            configuration = json.load(fh)
    except json.JSONDecodeError:
        raise json.JSONDecodeError(f"{recursive_sign} is not a valid JSON file.")

    recursive_signer = RecursiveSigner(envelope, configuration, kwargs["input_envelope"])
    return recursive_signer.recursive_sign()


def main(**kwargs) -> None:
    """Sign a SUIT envelope."""
    envelope = load_envelope(kwargs["input_envelope"])
    if kwargs["sign_subcommand"] == SIGN_SINGLE_LEVEL_CMD:
        envelope = single_level_sign(envelope, **kwargs)
    elif kwargs["sign_subcommand"] == SIGN_RECURSIVE_CMD:
        envelope = recursive_sign(envelope, **kwargs)
        pass
    else:
        raise GeneratorError(f"Invalid 'sign' subcommand: {kwargs['sign_subcommand']}")

    if envelope is None:
        raise ValueError("Signing the envelope failed - resulting envelope is empty.")
    save_envelope(kwargs["output_envelope"], envelope)
