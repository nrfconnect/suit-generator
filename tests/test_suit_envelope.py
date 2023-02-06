#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for SUIT internal envelope representation."""

import pytest
import binascii
from suit_generator.suit.envelope import SuitEnvelopeTagged
from suit_generator.suit.types.keys import suit_authentication_wrapper, suit_manifest

envelope_1_unsigned = (
    "d86ba2025827815824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5a"
    "f035871a50101020003585fa202818141000458568614a40150fa6b4a53d5ad5fdfbe9de663e4d41ffe025014"
    "92af1425695e48bf429b2d51f2ab45035824822f582000112233445566778899aabbccddeeff0123456789abc"
    "deffedcba98765432100e1987d0010f020f074382030f0943821702"
)

envelope_2_signed = (
    "d86ba2025873825824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af584ad2"
    "8443a10126a0f65840e3505f7ab70bd3a0e04916f37b0d7251aa6f52ca12c7edaa886a4129a298ca6a1ecc2a57955c6b"
    "f4ccb9f01d684d5d1c4774dffbe508a034431feafa60848a2c035871a50101020003585fa202818141000458568614a4"
    "0150fa6b4a53d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45035824822f58200011223344"
    "5566778899aabbccddeeff0123456789abcdeffedcba98765432100e1987d0010f020f074382030f0943821702"
)


def test_parse_unsigned_envelope():
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(envelope_1_unsigned))
    assert envelope.metadata.tag.name == "SUIT_Envelope_Tagged"
    assert envelope.metadata.tag.value == 107
    # fixme: remove/rework this ugly objects structure value.value.value - since it's not readable at all
    #   possible solutions:
    #    - method to solve full path, envelope.get_object(root, 'suit-authentication-wrapper') - ref to xml structures
    #    - dynamically added attributes - hard to use when converting between obj -> cbor -> obj
    #    - value stored as private variable and available as property?
    assert type(envelope.value.value.value) is dict
    assert suit_authentication_wrapper in envelope.value.value.value.keys()
    assert suit_manifest in envelope.value.value.value.keys()
    # fixme: corner case for extracting some sub items.
    assert (
        envelope.value.value.value[suit_authentication_wrapper].value[0].value.value.value[0].value
        == "cose-alg-sha-256"
    )


@pytest.mark.skip(reason="Signed envelopes are not supported")
def test_parse_signed_envelope():
    """Test if is possible to parse complete unsigned envelope."""
    envelope = SuitEnvelopeTagged.from_cbor(binascii.a2b_hex(envelope_2_signed))
    assert envelope.metadata.tag.name == "SUIT_Envelope_Tagged"
    assert envelope.metadata.tag.value == 107
    assert envelope.value.value.value is dict
    assert suit_authentication_wrapper in envelope.value.value.value.keys()
    assert suit_manifest in envelope.value.value.value.keys()
