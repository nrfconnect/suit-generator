#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for suit authentication parsing."""
import binascii
from suit_generator.suit.authentication import SuitAuthenticationWrapper


AUTHENTICATION_WRAPPER_DATA = "815824822f58206658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af"


def test_suit_authentication_wrapper_from_cbor_only_digest():
    """Check authentication-wrapper parsing for only digest in it."""

    suit_obj = SuitAuthenticationWrapper.from_cbor(binascii.a2b_hex(AUTHENTICATION_WRAPPER_DATA))
    assert suit_obj.value is not None


def test_suit_authentication_wrapper_from_cbor_only_digest_parse_and_dump():
    """Check authentication-wrapper parsing for only digest in it."""

    suit_obj = SuitAuthenticationWrapper.from_cbor(binascii.a2b_hex(AUTHENTICATION_WRAPPER_DATA))
    assert suit_obj.to_cbor().hex() == AUTHENTICATION_WRAPPER_DATA
