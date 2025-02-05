#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""A basic KMS based on keys stored in files on the local drive."""

import os

from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import math

from suit_generator.suit_kms_base import SuitKMSBase
import json


class SuitKMS(SuitKMSBase):
    """Implementation of the KMS."""

    def parse_context(self, context: str) -> None:
        """Parse the provided context string."""
        if context is None:
            self.keys_directory = Path(__file__).parent
            return None

        # Check if context is a valid path
        context_path = Path(context)
        if context_path.is_dir():
            self.keys_directory = context_path
            return

        try:
            context_loaded = json.loads(context)
        except json.JSONDecodeError:
            raise ValueError(f"The provided context '{context}' is neither a valid path nor a valid JSON string.")

        try:
            self.keys_directory = Path(context_loaded["keys_directory"])
        except KeyError:
            raise ValueError(f"The provided json context '{context}' does not contain the 'keys_directory' key.")

    def init_kms(self, context: str) -> None:
        """
        Initialize the KMS.

        :param context: The context to be used
        """
        self.parse_context(context)

    def encrypt(self, plaintext: bytes, key_name: str, context: str, aad: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt the plaintext with an AES key.

        :param plaintext: The plaintext to be encrypted.
        :param key_name: The name of the key to be used.
        :param context: The context to be used
                        If it is passed, it is used to point to the directory where the keys are stored.
                        It can either be a path or a JSON string in the format '{ "keys_directory":"<path>" }'.
        :param aad: The additional authenticated data to be used.
        :return: The nonce, tag and ciphertext.
        :rtype: tuple[bytes, bytes, bytes]
        """
        key_file_name = key_name + ".bin"
        key_file = self.keys_directory / key_file_name

        with open(key_file, "rb") as f:
            key_data = f.read()
        aesgcm = AESGCM(key_data)
        nonce = os.urandom(12)
        ciphertext_response = aesgcm.encrypt(nonce, plaintext, aad)
        ciphertext = ciphertext_response[:-16]
        tag = ciphertext_response[-16:]

        return nonce, tag, ciphertext

    def _verify_signing_key_type(self, private_key, algorithm: str) -> bool:
        """Verify if the key type matches the provided key."""
        if isinstance(private_key, EllipticCurvePrivateKey):
            return f"es-{private_key.key_size}" == algorithm
        elif isinstance(private_key, Ed25519PrivateKey) or isinstance(private_key, Ed448PrivateKey):
            return "eddsa" == algorithm
        else:
            raise ValueError(f"Key {type(private_key)} not supported")

    def _create_cose_es_signature(self, input_data, private_key) -> bytes:
        """Create ECDSA signature and return signature bytes."""
        hash_map = {256: hashes.SHA256(), 384: hashes.SHA384(), 521: hashes.SHA512()}
        dss_signature = private_key.sign(input_data, ec.ECDSA(hash_map[private_key.key_size]))
        r, s = decode_dss_signature(dss_signature)
        return r.to_bytes(math.ceil(private_key.key_size / 8), byteorder="big") + s.to_bytes(
            math.ceil(private_key.key_size / 8), byteorder="big"
        )

    def _create_cose_ed_signature(self, input_data, private_key) -> bytes:
        """Create ECDSA signature and return signature bytes."""
        return private_key.sign(input_data)

    def _get_sign_method(self, private_key) -> bool:
        """Return sign method based on key type."""
        if isinstance(private_key, EllipticCurvePrivateKey):
            return self._create_cose_es_signature
        elif isinstance(private_key, Ed25519PrivateKey) or isinstance(private_key, Ed448PrivateKey):
            return self._create_cose_ed_signature
        else:
            raise ValueError(f"Key {type(private_key)} not supported")

    def sign(self, data: bytes, key_name: str, algorithm: str, context: str) -> bytes:
        """
        Sign the data with a private key.

        :param data: The data to be signed.
        :param key_name: The name of the private key to be used.
        :param algorithm: The name of the algorithm to be used.
                          Used to verify if the key in the provided file contains a key of a compatible type.
        :param context: The context to be used

        :return: The signature.
        :rtype: bytes
        """
        if (self.keys_directory / key_name).with_suffix(".pem").is_file():
            key_file_name = key_name + ".pem"
            loader = load_pem_private_key
        elif (self.keys_directory / key_name).with_suffix(".der").is_file():
            key_file_name = key_name + ".der"
            loader = load_der_private_key
        else:
            raise ValueError(
                f"Key file {key_name} not found - neither {key_name}.pem nor {key_name}.der "
                + f"exists in {self.keys_directory}"
            )

        private_key_path = self.keys_directory / key_file_name

        with open(private_key_path, "rb") as private_key:
            private_key = loader(private_key.read(), None)

        if not self._verify_signing_key_type(private_key, algorithm):
            raise ValueError(f"Key {key_file_name} is not compatible with algorithm {algorithm}")

        sign_method = self._get_sign_method(private_key)
        signature = sign_method(data, private_key)

        return signature


def suit_kms_factory():
    """Get a KMS object."""
    return SuitKMS()
