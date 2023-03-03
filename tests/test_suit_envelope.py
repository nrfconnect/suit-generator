#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for SUIT internal envelope representation."""

import pytest
import binascii
from suit_generator.suit.envelope import SuitEnvelopeTagged
from suit_generator.suit.types.keys import suit_authentication_wrapper, suit_manifest, suit_manifest_sequence_number

ENVELOPE_1_UNSIGNED = (
    "d86ba2025827815824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5a"
    "f035871a50101020003585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe025014"
    "92af1425695e48bf429b2d51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abc"
    "deffedcba98765432100e1987d0010f020f074382030f0943821702"
)

ENVELOPE_2_UNSIGNED = (
    "d86ba3025827815824822f58201fa5ac823699866eea2636e35d8839b500edca78017293ec170ee46b93de1c5d"
    "03587fa701010201035839a2028181441e05400004582d8614a301502bdc1c07e0d15484be5063174d5a74c302"
    "508520ea9c515e57798b5fbdad67dec7d90e00010f020f074382030f0943821702114d8214a11568236170702e"
    "62696e17822f58203abeaa152b7b1af05d37eab6d31062288ed3d72f24cb5c51eb0e9dd90a124118175887a181"
    "441e054000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246353432305f6370"
    "75617070036d6e6f7264696373656d692e6e6f04781d546865206e52463533383430206170706c69636174696f"
    "6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e302e30"
)

ENVELOPE_3_UNSIGNED_NEGATIVE_SEQUENCE_NUMBER = (
    "d86ba3025827815824822f5820e66ba02fc45f1c8eef3af2f923dde400647340889a281fa5f28b3e123486a5c10"
    "35883a70101023a075bcd14035839a2028181441e05400004582d8614a301502bdc1c07e0d15484be5063174d5a"
    "74c302508520ea9c515e57798b5fbdad67dec7d90e00010f020f074382030f0943821702114d8214a1156823617"
    "0702e62696e17822f58203abeaa152b7b1af05d37eab6d31062288ed3d72f24cb5c51eb0e9dd90a124118175887"
    "a181441e054000a60178184e6f726469632053656d69636f6e647563746f7220415341026e6e5246353432305f6"
    "37075617070036d6e6f7264696373656d692e6e6f04781d546865206e52463533383430206170706c6963617469"
    "6f6e20636f726505781a53616d706c65206170706c69636174696f6e20636f7265204657066676312e302e30"
)

ENVELOPE_4_SIGNED = (
    "d86ba2025873825824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af584ad2"
    "8443a10126a0f65840e3505f7ab70bd3a0e04916f37b0d7251aa6f52ca12c7edaa886a4129a298ca6a1ecc2a57955c6b"
    "f4ccb9f01d684d5d1c4774dffbe508a034431feafa60848a2c035871a50101020003585fa202818141000458568614a4"
    "0150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45035824822f58200011223344"
    "5566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f074382030f0943821702"
)


def test_parse_unsigned_envelope():
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(ENVELOPE_1_UNSIGNED))
    assert envelope._metadata.tag.name == "SUIT_Envelope_Tagged"
    assert envelope._metadata.tag.value == 107
    assert type(envelope.value.value.value) is dict
    assert suit_authentication_wrapper in envelope.SuitEnvelopeTagged.value.SuitEnvelope.keys()
    assert suit_manifest in envelope.SuitEnvelopeTagged.value.SuitEnvelope.keys()
    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_authentication_wrapper]
        .SuitAuthenticationWrapper[0]
        .SuitAuthentication.SuitDigest.SuitDigestRaw[0]
        .SuitCoseHashAlg
        == "cose-alg-sha-256"
    )


def test_parse_unsigned_envelope_1_parsing_dumping():
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(ENVELOPE_1_UNSIGNED))
    assert envelope.to_cbor().hex() == ENVELOPE_1_UNSIGNED


def test_parse_unsigned_envelope_2_parsing_dumping():
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(ENVELOPE_2_UNSIGNED))
    assert envelope.to_cbor().hex() == ENVELOPE_2_UNSIGNED


def test_parse_unsigned_envelope_3_parsing_dumping_negative():
    """Test if is possible to parse complete unsigned envelope containing negative sequence number."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(ENVELOPE_3_UNSIGNED_NEGATIVE_SEQUENCE_NUMBER))
    assert envelope.to_cbor().hex() == ENVELOPE_3_UNSIGNED_NEGATIVE_SEQUENCE_NUMBER
    assert (
        envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest].SuitManifest[suit_manifest_sequence_number].value
        == -123456789
    )


@pytest.mark.skip(reason="Signed envelopes are not supported")
def test_parse_signed_envelope():
    """Test if is possible to parse complete signed envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(ENVELOPE_4_SIGNED))
    assert envelope.metadata.tag.name == "SUIT_Envelope_Tagged"
    assert envelope.metadata.tag.value == 107
    assert envelope.value.value.value is dict
    assert suit_authentication_wrapper in envelope.value.value.value.keys()
    assert suit_manifest in envelope.value.value.value.keys()
