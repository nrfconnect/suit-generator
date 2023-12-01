#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""CMD_KEYS CLI command entry point."""

from __future__ import annotations
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from suit_generator.exceptions import GeneratorError

KEYS_CMD = "keys"


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_keys_arg_parser = parser.add_parser(KEYS_CMD, help="Create pair of signing keys.")
    cmd_keys_arg_parser.add_argument("--output-file", required=True, help="Prefix for output files.")
    cmd_keys_arg_parser.add_argument(
        "--type",
        required=False,
        default=KeyGenerator.default_key_type,
        help=f"Output key file type. Default: {KeyGenerator.default_key_type}",
        choices=KeyGenerator.supported_key_types.keys(),
    )
    cmd_keys_arg_parser.add_argument(
        "--encoding",
        required=False,
        default=KeyGenerator.default_encoding,
        help=f"Key encoding. Default: {KeyGenerator.default_encoding}",
        choices=KeyGenerator.supported_encodings.keys(),
    )
    cmd_keys_arg_parser.add_argument(
        "--private-format",
        required=False,
        default=KeyGenerator.default_private_format,
        help=f"Private key format. Default: {KeyGenerator.default_private_format}",
        choices=KeyGenerator.supported_private_formats.keys(),
    )
    cmd_keys_arg_parser.add_argument(
        "--public-format",
        required=False,
        default=KeyGenerator.default_public_format,
        help=f"Public key format. Default: {KeyGenerator.default_public_format}",
        choices=KeyGenerator.supported_public_formats.keys(),
    )
    cmd_keys_arg_parser.add_argument(
        "--encryption",
        required=False,
        default=KeyGenerator.default_encryption,
        help=f"Key encryption. Default: {KeyGenerator.default_encryption}",
        choices=KeyGenerator.supported_encryptions.keys(),
    )


class KeyGenerator:
    """Key pair generator."""

    # Key types supported by KeyGenerator.
    # secp* curves are mapped to their corresponding classes for easier instantiation.
    # ed* curves use different approach and don't need such mapping.
    supported_key_types = {
        "secp256r1": ec.SECP256R1,
        "secp384r1": ec.SECP384R1,
        "secp521r1": ec.SECP521R1,
        "ed25519": None,
        "ed448": None,
    }
    default_key_type = "secp256r1"

    # Key encodings supported by KeyGenerator.
    supported_encodings = {
        "pem": Encoding.PEM,
        "der": Encoding.DER,
    }
    default_encoding = "pem"

    # Private key formats supported by KeyGenerator.
    # Note: Some formats might not be available for some key types
    supported_private_formats = {
        "pkcs1": PrivateFormat.TraditionalOpenSSL,
        "pkcs8": PrivateFormat.PKCS8,
    }
    default_private_format = "pkcs8"

    # Public key formats supported by KeyGenerator.
    # Note: Some formats might not be available for some key types
    supported_public_formats = {
        "default": PublicFormat.SubjectPublicKeyInfo,
        "pkcs1": PublicFormat.PKCS1,
    }
    default_public_format = "default"

    # Encryption algorithms supported by KeyGenerator.
    supported_encryptions = {
        "none": NoEncryption(),
    }
    default_encryption = "none"

    def _write(self, data: bytes, file_name: str):
        """Write binary data to a file."""
        with open(file_name, "wb") as fd:
            fd.write(data)

    def _write_keypair(self, private: bytes, public: bytes, file_name_prefix: str, encoding: str):
        """Write private and public key data to files sharing common file name base."""
        self._write(private, f"{file_name_prefix}_priv.{encoding}")
        self._write(public, f"{file_name_prefix}_pub.{encoding}")

    def generate_private_key(self, type: str) -> EllipticCurvePrivateKey | Ed25519PrivateKey | Ed448PrivateKey:
        """Generate and returns private key object."""
        if type in ("secp256r1", "secp384r1", "secp521r1"):
            return ec.generate_private_key(KeyGenerator.supported_key_types[type])
        elif type == "ed25519":
            return Ed25519PrivateKey.generate()
        elif type == "ed448":
            return Ed448PrivateKey.generate()
        else:
            raise TypeError(f"{type} not supported")

    def create_key_pair(
        self,
        file_name_prefix: str,
        key_type: str,
        encoding: str,
        private_format: str,
        public_format: str,
        encryption: str,
    ):
        """Create a pair of keys and store them in files sharing their name prefix."""
        private_key = self.generate_private_key(key_type)
        public_key = private_key.public_key()

        try:
            private_key_bytes = private_key.private_bytes(
                KeyGenerator.supported_encodings[encoding],
                KeyGenerator.supported_private_formats[private_format],
                KeyGenerator.supported_encryptions[encryption],
            )

            public_key_bytes = public_key.public_bytes(
                KeyGenerator.supported_encodings[encoding], KeyGenerator.supported_public_formats[public_format]
            )

            self._write_keypair(private_key_bytes, public_key_bytes, file_name_prefix, encoding)

        except ValueError as error:
            raise GeneratorError(f"Invalid key generator parameters combination: {error}") from error
        except FileNotFoundError as error:
            raise GeneratorError(f"Invalid path: {error}") from error


def main(output_file: str, type: str, encoding: str, private_format: str, public_format: str, encryption: str) -> None:
    """Create signing keys.

    :param output_file: file name prefix for key files
    :param type: output file type
    :param encoding: encoding of key files
    :param private_format: format of private key file
    :param public_format: format of public key file
    :param encryption: encryption algorithm for key files
    """
    key_gen = KeyGenerator()
    key_gen.create_key_pair(output_file, type, encoding, private_format, public_format, encryption)
