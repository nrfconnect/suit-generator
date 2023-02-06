#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for suit authentication parsing."""
import binascii
from suit_generator.suit.authentication import SuitAuthenticationWrapper


def test_suit_authentication_wrapper_from_cbor_only_digest():
    """Check authentication-wrapper parsing for only digest in it."""
    data = "815824822F58206658EA560262696DD1F13B782239A064DA7C6C5CBAF52FDED428A6FC83C7E5AF"

    suit_obj = SuitAuthenticationWrapper.from_cbor(binascii.a2b_hex(data))
    assert suit_obj.value is not None
