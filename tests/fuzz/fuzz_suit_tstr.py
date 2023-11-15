#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Fuzz SiuitTstr.

Is expected that this fuzzer will report a lot of exceptions for this particular script since cbor2 library is
not very good at untrusted input parsing.

Just consider exceptions found so far under Ubuntu:
# exception -> payload in hex:
# OverflowError: cbor2.loads(binascii.a2b_hex('c11b9b9b9b0000000000'))
# OSError: cbor2.loads(binascii.a2b_hex('c11b1616161616161616161616161616'))
# MemoryError: cbor2.loads(binascii.a2b_hex('95393b7b7b7b7b7b7b7b7b7b7b7b7b7b'))
# TypeError: cbor2.loads(binascii.a2b_hex('d8250010600000006010000000000000'))
# SystemError: cbor2.loads(binascii.a2b_hex('d81e84ffffffff'))
# re.error: cbor2.loads(binascii.a2b_hex('d8234129'))
"""

import sys
import atheris

with atheris.instrument_imports():
    from suit_generator.suit.types.common import SuitTstr


def fuzz_tstr(data):
    """Fuzz yaml input."""
    try:
        fdp = atheris.FuzzedDataProvider(data)
        fuzz_bytes = fdp.ConsumeBytes(16)
        SuitTstr.from_cbor(fuzz_bytes)
    except ValueError:
        # ValueError is expected for some payloads since it's used by all suit-generator levels to report
        # not valid data.
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, fuzz_tstr)
    atheris.Fuzz()
