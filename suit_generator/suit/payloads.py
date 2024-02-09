#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""SUIT envelope integrated payloads representation."""
import pathlib
import string

from suit_generator.suit.types.common import SuitKeyValueUnnamed, SuitTstr, Metadata, SuitHex


class SuitIntegratedPayloadMap(SuitKeyValueUnnamed):
    """Representation of SUIT payloads."""

    _metadata = Metadata(map={SuitTstr: SuitHex})

    @classmethod
    def from_obj(cls, obj: dict) -> SuitKeyValueUnnamed:
        """Restore SUIT representation from passed object."""
        ret = {}
        for k, v in obj.items():
            if all(c in string.hexdigits for c in v):
                data = v
            elif isinstance(v, dict):
                # called here to avoid circular import
                from suit_generator.suit.envelope import SuitEnvelopeTagged

                binary_data = SuitEnvelopeTagged.return_processed_binary_data(v)
                data = binary_data.hex().upper()
            elif pathlib.Path.is_file(pathlib.Path(v)):
                with open(v, "rb") as fh:
                    data = fh.read().hex().upper()
            else:
                raise ValueError(f"Unable to parse {obj}")
            for c_k, c_v in cls._metadata.map.items():
                try:
                    key = c_k.from_obj(k)
                    ret[k] = (key, c_v.from_obj(data))
                    break
                except ValueError:
                    pass
            else:
                raise ValueError(f"Unable to parse key-value pair: {k}: {v}")
        return cls(ret)
