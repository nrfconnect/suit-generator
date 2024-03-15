#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for ncs example signing script."""
import shutil

import pytest
import binascii
import pathlib
import os
import cbor2
import subprocess
import sys
import uuid

from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from suit_generator.suit.authentication import CoseSigStructure
from suit_generator.suit.envelope import SuitEnvelopeTagged

from suit_generator.suit.types.keys import (
    suit_authentication_wrapper,
    suit_integrated_payloads,
    suit_cose_algorithm_id,
    suit_cose_key_id,
)

from ncs.sign_script import Signer, SignerError

TEMP_DIRECTORY = pathlib.Path("test_test_data")

PRIVATE_KEYS = {
    "ES_256": b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCCbgTEad8JOIU8sg
IJUKm7Lle0358XoaxNfbs4nqd4WhRANCAATt0J6l7OTtvmwI50cJVZo4KcUxMyJ7
9PARbowFLQIODsPg2Df0wm/BKIAvRTgaIytt1dooYABdq+Kgg9vvOFUT
-----END PRIVATE KEY-----""",
    "ES_384": b"""-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCw/iNctq9pFyKI/fem
p/CmNMyMyMnM29D4aajftXjkJQJv/ei/jTWFV5RbyBQiU8mhZANiAATp3RsCAE7E
C+9ywexwCwCqFS5thWjpXJfcrN+KaqRJ65H5r1cHmZB7sLj/qIPgclrNWA+qau7H
SybGG+k1OCi30FZSSo7Ozv8jarYr8NvoQnyI6+01Mo5TaOqC9a+41p8=
-----END PRIVATE KEY-----
""",
    "ES_521": b"""-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB+FeSvnnlrN47qdge
TO/tO6YhB9uzWbk75EZlGkXPdR24dEgCdHJ5kYi7O01Zj8Qq5HBkdU7xE98vyJRD
fM0qjUOhgYkDgYYABAG0p3FRhnknwe7NJA4d8a70yo5068yvJsEnKVBIFQW5bptW
Rl4Ca2KpIMJF2EJW2JzQvb7EtDlDbhO+16XIC4XiZwFC3r/xdMtIlvuwiLI66kXg
FllgzoE3Rc2ZeGLOuD2SGi9H6iVhwynzSIl7RWnfhW8PtC2bT0smQ7D4YP9aO/k0
1g==
-----END PRIVATE KEY-----
""",
    "Ed25519": b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBiOzhb2OjnrKpySHYKDeeFbKHZdQzitUKd/plugHOJ6
-----END PRIVATE KEY-----
""",
    "RS2048": b"""-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCm+9OpJSZuKvOk
NUoRtnJp3npoorOi5gkbug0g9c8c8D+iOcvRdkz02mj9Nb5UGZFznQjXWcVvbDN5
IRiEbvK9TgepP4o8rTD8fhtMcdHUn273XKgXuFhHzeKTvLLVl9Faz5ABVMWenEC4
a/6sgmqo7acJAqYF0N9Nj4z68aVbtrC0eQhtmRfYf/gZnJ+iOa8pt9ss47PUEmL9
xxuAQpVkXjHbsvPs7++UhTxwBjZS0A03P7MdbQVe2dNzD25vAr/NgUs0UX8HMFwP
4BB1ialW8JbZ7btdxdjvJFIaAIa7HMxit+fr1JZXVmvOQ0dXZimW0mJobrcQzD8u
0xJZClRVAgMBAAECggEADkpByFliCw6I8DYRQyfKbc34ysiVt+yYvfMzmWz/zvmu
cGsiyqelmVSxpG27foX7oRnAvnEzyL/JPeX7q6W1B0dMt4q1AVFO/mSqYGXjL59/
RxL6XaFMiMSRTdRZt5a4910I9Vw0V0kG7uFrF4dHqnJAF7DO1XOVEJWm2njgjlMW
LOuqZMaST3VdNkzodbYkomO+is2cEraKCnJA1kUS4aoFaJTuw0fKEEKs9wRNDoJ6
5GIjYgnOI3H66OwfGRPgdaut1kg5hEGVGV8hUmkzo+5gPqlm6Vecx0cdWyqGw4QZ
Fy16Mu9uFME2TRWFl7JjoC0ni+gjJYfrg4Wimm+1lwKBgQDXC1DLSUTLbDThue7R
ZSR9w8sgjXRc4AtuetfQD9g02PKasgUb42FskpIUuFzDhMLdtaPHTr/ZEf3egxSF
QcFEkLIt7uuDPEQ6OqP79fISAUBI+x2f7/0zvuCcc+B2SzmA0n3zN++FRoVt/cGr
afQAiLlPOWd0aqHuNZECVtCUOwKBgQDGyUaUE1P/dtRPskSgre9zms9cC09ZISRi
crej93AB44ranxXUjv9acyN1yM/yWH26UahY5A1z/0HdqbVNIVf1uUbRaS5lqsim
V61563NBYQ21ahGyF4N80g7ejo4SZdovIwSC3jmCWSCjsp3seyD9JD7tYwhOyHEQ
Y31w4w8ArwKBgFHfxQshAkhREnE+0WZ4E8SuXxAtyzfxNWkC7FgTMEYus2+ih79u
exFTXLr21pq6WVcAaTLhELoc14N4dL+noWXxkWVbqd91eqSQ3w53PYsNXuRqd4UF
YmnpKqtmkvd2/JXHjpyjl1Yu225dRvd0h6oMZEF9oZ35W13Olz9EvnUxAoGAUz1n
W4w4aUomH3VDvZD4Kw2RdTabNHRnWv40nel4MqJIu8FQD+ENVp/OIn1DbnTVuRaG
iyp7463os9xjufeTcKbz267Sqen4+YbPcrVAXwk4B1ZyMIQeID+J0HIbVeLmmURt
mCtcI5QU0ddyv9rTdo0d+KO2j97pUXaHyaSa3KsCgYBJLasw5iYT4tgmtDs8jCs2
E7TSEscV8R+zLpRQv2ioC7bSXtGknmqlYJoTqzYsc1TxohhASbo2jxvIL79z+jtw
iOaKLTZVbAW/yjd5RbXO42PdpzRMu2vEvLvYhIWyQkHjO/kUHZa/01Syh0km6mb/
CrpU0XDa8s80x8DY4PqV4A==
-----END PRIVATE KEY-----
""",
}


TEST_DATA = {
    "ENVELOPE_1_UNSIGNED": (
        "d86ba2025827815824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5a"
        "f035871a50101020003585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe025014"
        "92af1425695e48bf429b2d51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abc"
        "deffedcba98765432100e1987d0010f020f074382030f0943821702"
    ),
    "ENVELOPE_2_UNSIGNED_COMPONENT_ID": (
        "D86BA2025827815824822F58209C1D3533ABDC3CFFCB81ADDA3E5A1655D3C705AE8D9ACD4213AD89DC7BCB37B"
        "50358A1A701010201035869A2028184414D4102451A0E0AA000451A000560000458528214A401507617DAA571"
        "FD5A858F94E28D735CE9F4025008C1B59955E85FBC9E767BC29CE1B04D035824822F58205F70BF18A08600701"
        "6E948B04AED3B82103A36BEA41755B6CDDFAF10ACE3C6EF0E190400094382170211508414A115692366696C65"
        "2E62696E150217822F4005824149500DAB491F1E1F53D4AEA1CA3C67A4EBE5"
    ),
    "ENVELOPE_6_UNSIGNED_COMPONENT_LIST": (
        "d86ba2025827815824822f582071395a66f9cb583dbdc797ad6cd5d101531b14c082802b491c5c6745774c748003588a"
        "a701010201035844a2028184414d4102451a0e054000451a0005600004582d8614a301507617daa571fd5a858f94e28d"
        "735ce9f40250d622bafd4337518590bc6368cda7fbca0e00010f020f074382030f0943821702114d8214a11568236170"
        "702e62696e17822f58202ba46bc4a70d125b30c4227985578eb6a889807a939cc148b4d8110d4f2ed940"
    ),
    "ENVELOPE_7_UNSIGNED_TWO_INTEGRATED_PAYLOADS": (
        "D86BA4025827815824822F582087EC80F16398B14294B0978D507DB9E4FF23C00463C072762B32D4A30212CCFA0359010FA601"
        "0102050358B4A2028384414D4102451A1E0AA000451A0007F800824144410084414D4103451A1E054000451A00055800045887"
        "900C0014A201507617DAA571FD5A858F94E28D735CE9F40250D622BAFD4337518590BC6368CDA7FBCA010F020F0CF514A20358"
        "24822F5820374708FFF7719DD5979EC875D56CD2286F6D3CF7EC317A3B25632AAB28EC37BB0E100C0214A2035824822F582037"
        "4708FFF7719DD5979EC875D56CD2286F6D3CF7EC317A3B25632AAB28EC37BB0E100749880C00030F0C02030F0949880C021702"
        "0C00170211583A981E0C0114A11568236170702E62696E1502030F0C0014A116011602030F0C0114A1156A23726164696F2E62"
        "696E15020C0214A116011602030F68236170702E62696E50000000000000000000000000000000006A23726164696F2E62696E"
        "5000000000000000000000000000000000"
    ),
}


@pytest.fixture
def setup_and_teardown(tmp_path_factory):
    """Create and cleanup environment."""
    # Setup environment
    #   - create required files in TEMP_DIRECTORY
    start_directory = os.getcwd()
    path = tmp_path_factory.mktemp(TEMP_DIRECTORY)
    os.chdir(path)
    with open("key_private_es_256.pem", "wb") as fh:
        fh.write(PRIVATE_KEYS["ES_256"])
    with open("key_private_es_384.pem", "wb") as fh:
        fh.write(PRIVATE_KEYS["ES_384"])
    with open("key_private_es_521.pem", "wb") as fh:
        fh.write(PRIVATE_KEYS["ES_521"])
    with open("key_private_ed25519.pem", "wb") as fh:
        fh.write(PRIVATE_KEYS["Ed25519"])
    with open("key_private_rs2048.pem", "wb") as fh:
        fh.write(PRIVATE_KEYS["RS2048"])
    with open("test_envelope.suit", "wb") as fh:
        fh.write(binascii.a2b_hex(TEST_DATA["ENVELOPE_1_UNSIGNED"]))
    with open("test_envelope_manifest_component_id.suit", "wb") as fh:
        fh.write(binascii.a2b_hex(TEST_DATA["ENVELOPE_2_UNSIGNED_COMPONENT_ID"]))
    yield
    # Cleanup environment
    #   - remove temp directory
    os.chdir(start_directory)


def test_ncs_cose(setup_and_teardown):
    """Test if is possible to create cose structure using ncs sign_script.py."""
    signer = Signer()
    signer.load_envelope("test_envelope.suit")
    cose_binary = signer.create_cose_structure({1: -7})
    cose_cbor = cbor2.loads(cose_binary)
    assert isinstance(cose_cbor, list)


def test_ncs_auth_block(setup_and_teardown):
    """Test if is possible to create authentication block using ncs sign_script.py."""
    signer = Signer()
    signer.load_envelope("test_envelope.suit")
    auth_block = signer.create_authentication_block({}, {}, b"\xDE\xAD\xBE\xEF")
    assert isinstance(auth_block, cbor2.CBORTag)


def test_ncs_get_digest_object(setup_and_teardown):
    """Test if is possible to extract digest object using ncs sign_script.py."""
    signer = Signer()
    signer.load_envelope("test_envelope.suit")
    assert signer.get_digest() == [
        -16,
        binascii.a2b_hex("6658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af"),
    ]


@pytest.mark.parametrize(
    "private_key",
    ["es_256", "es_384", "es_521", "ed25519"],
)
def test_ncs_signing(setup_and_teardown, private_key):
    """Test if is possible to sign manifest."""
    signer = Signer()
    signer.load_envelope("test_envelope.suit")
    signer.sign(f"key_private_{private_key}.pem")
    signer.save_envelope("test_envelope_signed.suit")

    with open("test_envelope_signed.suit", "rb") as fh:
        envelope = SuitEnvelopeTagged.from_cbor(fh.read())

    assert envelope is not None
    assert suit_authentication_wrapper in envelope.SuitEnvelopeTagged.value.SuitEnvelope
    assert hasattr(envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper], "SuitAuthentication")
    assert hasattr(
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper].SuitAuthentication[1],
        "SuitAuthenticationBlock",
    )
    assert len(envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper].SuitAuthentication) == 2
    assert hasattr(
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper].SuitAuthentication[0],
        "SuitDigest",
    )


@pytest.mark.parametrize(
    "input_data, amount_of_payloads",
    [("ENVELOPE_6_UNSIGNED_COMPONENT_LIST", 0), ("ENVELOPE_7_UNSIGNED_TWO_INTEGRATED_PAYLOADS", 2)],
)
def test_envelope_sign_and_verify(setup_and_teardown, input_data, amount_of_payloads):
    """Sign an envelope and verify signature using public key."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA[input_data]))
    if amount_of_payloads > 0:
        assert (
            len(envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_integrated_payloads].SuitIntegratedPayloadMap)
            == amount_of_payloads
        )
    digest_object = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[0]
        .SuitDigest.to_obj()
    )

    with open("test_envelope.suit", "wb") as fh:
        fh.write(envelope.to_cbor())

    signer = Signer()
    signer.load_envelope("test_envelope.suit")
    signer.sign("key_private_es_256.pem")
    signer.save_envelope("test_envelope_signed.suit")

    with open("test_envelope_signed.suit", "rb") as fh:
        envelope = SuitEnvelopeTagged.from_cbor(fh.read())

    signature = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[3]
        .SuitHex
    )
    # extract r and s from signature and decode_signature
    int_sig = int.from_bytes(signature, byteorder="big")
    r = int_sig >> (32 * 8)
    s = int_sig & sum([0xFF << x * 8 for x in range(0, 32)])
    dss_signature = encode_dss_signature(r, s)
    algorithm_name = (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[0]
        .SuitHeaderMap[suit_cose_algorithm_id]
        .value
    )
    cose_structure = CoseSigStructure.from_obj(
        {
            "context": "Signature1",
            "body_protected": {"suit-cose-algorithm-id": algorithm_name, "suit-cose-key-id": 0x7FFFFFE0},
            "external_add": "",
            "payload": digest_object,
        }
    )
    binary_data = cose_structure.to_cbor()

    public_key = load_pem_private_key(PRIVATE_KEYS["ES_256"], None).public_key()
    public_key.verify(dss_signature, binary_data, ec.ECDSA(hashes.SHA256()))


def test_ncs_signing_unsupported(setup_and_teardown):
    """Test if SignerError is raised in case of unsupported key used."""
    signer = Signer()
    signer.load_envelope("test_envelope.suit")
    with pytest.raises(SignerError):
        signer.sign("key_private_rs2048.pem")


@patch("ncs.sign_script.DEFAULT_KEY_ID", 0x0C0FFE)
def test_ncs_signing_manifest_component_id_known_default_key_used(setup_and_teardown):
    """Test if default key id is selected in case of unknown suit-manifest-component-id received."""
    signer = Signer()
    signer.load_envelope("test_envelope_manifest_component_id.suit")
    parsed_manifest_id = signer._get_manifest_class_id()

    domain_name = uuid.uuid5(uuid.NAMESPACE_DNS, "nordicsemi.com")
    expected_manifest_id = uuid.uuid5(domain_name, "unit_test_envelope").hex

    assert parsed_manifest_id == expected_manifest_id

    signer.sign("key_private_es_256.pem")
    signer.save_envelope("test_envelope_signed.suit")

    with open("test_envelope_signed.suit", "rb") as fh:
        envelope = SuitEnvelopeTagged.from_cbor(fh.read())

    assert envelope is not None
    assert suit_authentication_wrapper in envelope.SuitEnvelopeTagged.value.SuitEnvelope
    assert hasattr(envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper], "SuitAuthentication")
    assert hasattr(
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper].SuitAuthentication[1],
        "SuitAuthenticationBlock",
    )
    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[0]
        .SuitHeaderMap[suit_cose_key_id]
        .value
        == 0x0C0FFE
    )


@patch("ncs.sign_script.KEY_IDS", {"unit_test_envelope": 0xFFEEDDBB, "some_other_sample": 0xFFFFFFFF})
def test_ncs_signing_manifest_component_id_known_non_default(setup_and_teardown):
    """Test if key_id is selected according to the received suit-manifest-component-id."""
    signer = Signer()
    signer.load_envelope("test_envelope_manifest_component_id.suit")

    signer.sign("key_private_es_256.pem")
    signer.save_envelope("test_envelope_signed.suit")

    with open("test_envelope_signed.suit", "rb") as fh:
        envelope = SuitEnvelopeTagged.from_cbor(fh.read())

    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[0]
        .SuitHeaderMap[suit_cose_key_id]
        .value
        == 0xFFEEDDBB
    )


@patch("ncs.sign_script.DEFAULT_KEY_ID", 0xDEADBEEF)
def test_ncs_signing_manifest_component_id_unknown(setup_and_teardown):
    """Test if default key_id is used in case of not available suit-manifest-class-id."""
    signer = Signer()
    signer.load_envelope("test_envelope_manifest_component_id.suit")

    signer.sign("key_private_es_256.pem")
    signer.save_envelope("test_envelope_signed.suit")

    with open("test_envelope_signed.suit", "rb") as fh:
        envelope = SuitEnvelopeTagged.from_cbor(fh.read())

    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthentication[1]
        .SuitAuthenticationBlock.CoseSign1Tagged.value.CoseSign1[0]
        .SuitHeaderMap[suit_cose_key_id]
        .value
        == 0xDEADBEEF
    )


def test_ncs_sign_cli_interface(setup_and_teardown):
    """Test if is possible to call cli interface."""
    shutil.copyfile(
        "key_private_es_256.pem",
        pathlib.Path(os.path.dirname(os.path.abspath(__file__))).parent / "ncs" / "key_private.pem",
    )
    completed_process = subprocess.run(
        [
            sys.executable,
            pathlib.Path(os.path.dirname(os.path.abspath(__file__))).parent / "ncs" / "sign_script.py",
            "--input-file",
            "test_envelope.suit",
            "--output-file",
            "test_envelope_signed_cli.suit",
        ]
    )
    assert completed_process.returncode == 0
