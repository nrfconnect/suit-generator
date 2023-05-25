#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for types/common.py implementation."""
from suit_generator.suit.types.common import SuitInt, SuitBool, SuitTstr, cbstr
import pytest


@pytest.mark.parametrize(
    "suit_item, input_data",
    [
        (SuitInt, 0),
        (SuitInt, 1),
        (SuitInt, -1),
        (SuitInt, 0x0E100000),
        (SuitInt, 0xBEEF),
        (SuitBool, True),
        (SuitBool, False),
        (cbstr(SuitBool), True),
        (cbstr(SuitBool), False),
        (SuitTstr, ""),
        (SuitTstr, "Test 1234"),
        (SuitTstr, "1234"),
        (SuitTstr, "True"),
        (SuitTstr, "true"),
        (SuitTstr, "74727565"),
        (SuitTstr, "010203"),
        (SuitTstr, "M"),
        (SuitTstr, " "),
    ],
)
def test_simple_suit_representation(suit_item, input_data):
    suit_obj = suit_item.from_obj(input_data)
    assert getattr(suit_obj, suit_item.__name__) == input_data
