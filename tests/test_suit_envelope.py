#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for SUIT internal envelope representation."""

import pytest
import binascii
from suit_generator.suit.envelope import SuitEnvelopeTagged
from suit_generator.suit.types.keys import (
    suit_authentication_wrapper,
    suit_manifest,
    suit_manifest_sequence_number,
    suit_manifest_version,
    suit_common,
)

TEST_DATA = {
    "ENVELOPE_1_UNSIGNED": (
        "d86ba2025827815824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5a"
        "f035871a50101020003585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe025014"
        "92af1425695e48bf429b2d51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abc"
        "deffedcba98765432100e1987d0010f020f074382030f0943821702"
    ),
    "ENVELOPE_2_UNSIGNED": (
        "d86ba4025827815824822f5820d8e4fb7c2a95b0ef8d56d55641d1ea214f503b33af4aa348768c453e1d029d9"
        "f0358bba70101020203585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe025014"
        "92af1425695e48bf429b2d51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abc"
        "deffedcba98765432100e1987d0010f020f074382030f094382170211822f5820cfa90c5c58595e7f5119a72f"
        "803fd0370b3e6abbec6315cd38f63135281bc49817822f58209b9d629701fc35ffca609f9244267fb25c8703b"
        "9b3ff9820c66576e0cf976f9611586f8614a1157865687474703a2f2f6578616d706c652e636f6d2f76657279"
        "2f6c6f6e672f706174682f746f2f66696c652f66696c652f3132332f3435362f3738392f6162632f6465662f6"
        "768692f6a6b6c2f6d6e6f2f7072732f7475762f7778792f7a2f66696c652e62696e1502030f1759019ca20179"
        "01727465737420656e76656c6f706520666f7220737569742d67656e657261746f722c2077697468207665727"
        "9206c6f6e6720737472696e67206162636465666768696a6b6c6d6f6e6f70727374757778797a313233343536"
        "3738396162636465666768696a6b6c6d6f6e6f70727374757778797a313233343536373839616263646566676"
        "8696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f7072"
        "7374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a3132333"
        "435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465"
        "666768696a6b6c6d6f6e6f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6"
        "f70727374757778797a3132333435363738396162636465666768696a6b6c6d6f6e6f70727374757778797a31"
        "32333435363738395c6e5c6e5c6e5c6e814100a4036d6e6f7264696373656d692e6e6f0464737569740564746"
        "57374066476313233"
    ),
    "ENVELOPE_3_UNSIGNED": (
        "d86ba3025827815824822f58201fa5ac823699866eea2636e35d8839b500edca78017293ec170ee46b93de1c5d"
        "03587fa701010201035839a2028181441e05400004582d8614a301502bdc1c07e0d15484be5063174d5a74c302"
        "508520ea9c515e57798b5fbdad67dec7d90e00010f020f074382030f0943821702114d8214a11568236170702e"
        "62696e17822f58203abeaa152b7b1af05d37eab6d31062288ed3d72f24cb5c51eb0e9dd90a124118175887a181"
        "441e054000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246353432305f6370"
        "75617070036d6e6f7264696373656d692e6e6f04781d546865206e52463533383430206170706c69636174696f"
        "6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e302e30"
    ),
    "ENVELOPE_4_UNSIGNED_NEGATIVE_SEQUENCE_NUMBER": (
        "d86ba3025827815824822f5820e66ba02fc45f1c8eef3af2f923dde400647340889a281fa5f28b3e123486a5c10"
        "35883a70101023a075bcd14035839a2028181441e05400004582d8614a301502bdc1c07e0d15484be5063174d5a"
        "74c302508520ea9c515e57798b5fbdad67dec7d90e00010f020f074382030f0943821702114d8214a1156823617"
        "0702e62696e17822f58203abeaa152b7b1af05d37eab6d31062288ed3d72f24cb5c51eb0e9dd90a124118175887"
        "a181441e054000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246353432305f6"
        "37075617070036d6e6f7264696373656d692e6e6f04781d546865206e52463533383430206170706c6963617469"
        "6f6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e302e30"
    ),
    "ENVELOPE_5_SIGNED": (
        "d86ba2025873825824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af584ad2"
        "8443a10126a0f65840e3505f7ab70bd3a0e04916f37b0d7251aa6f52ca12c7edaa886a4129a298ca6a1ecc2a57955c6b"
        "f4ccb9f01d684d5d1c4774dffbe508a034431feafa60848a2c035871a50101020003585fa202818141000458568614a4"
        "0150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45035824822f58200011223344"
        "5566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f074382030f0943821702"
    ),
}


@pytest.mark.parametrize("input_envelope", ["ENVELOPE_1_UNSIGNED", "ENVELOPE_2_UNSIGNED", "ENVELOPE_3_UNSIGNED"])
def test_parse_unsigned_envelope(input_envelope):
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA[input_envelope]))
    # check if envelope contains dict
    assert type(envelope.SuitEnvelopeTagged.value.SuitEnvelope) is dict
    # check if authentication wrapper is available
    assert suit_authentication_wrapper in envelope.SuitEnvelopeTagged.value.SuitEnvelope.keys()
    # check if suit manifest is available
    assert suit_manifest in envelope.SuitEnvelopeTagged.value.SuitEnvelope.keys()
    # check if proper hash algorithm is used
    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthenticationWrapper[0]
        .SuitAuthentication.SuitDigest.SuitDigestRaw[0]
        .SuitCoseHashAlg
        == "cose-alg-sha-256"
    )
    # check if required items are available
    for required_item in [suit_manifest_sequence_number, suit_manifest_version, suit_common]:
        assert required_item in envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest.keys()


@pytest.mark.parametrize("input_envelope", ["ENVELOPE_1_UNSIGNED", "ENVELOPE_2_UNSIGNED", "ENVELOPE_3_UNSIGNED"])
def test_parse_unsigned_envelope_parse_and_dump(input_envelope):
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA[input_envelope]))
    assert envelope.to_cbor().hex() == TEST_DATA[input_envelope]


def test_parse_unsigned_envelope_parse_and_dump_negative_seq_number():
    """Test if is possible to parse complete unsigned envelope containing negative sequence number."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA["ENVELOPE_4_UNSIGNED_NEGATIVE_SEQUENCE_NUMBER"]))
    assert envelope.to_cbor().hex() == TEST_DATA["ENVELOPE_4_UNSIGNED_NEGATIVE_SEQUENCE_NUMBER"]
    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest[suit_manifest_sequence_number].value
        == -123456789
    )


@pytest.mark.skip(reason="Signed envelopes are not supported")
def test_parse_signed_envelope():
    """Test if is possible to parse complete signed envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(TEST_DATA["ENVELOPE_5_SIGNED"]))
    assert envelope.metadata.tag.name == "SUIT_Envelope_Tagged"
    assert envelope.metadata.tag.value == 107
    assert envelope.value.value.value is dict
    assert suit_authentication_wrapper in envelope.value.value.value.keys()
    assert suit_manifest in envelope.value.value.value.keys()
