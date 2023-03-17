#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""SUIT envelope integrated payloads representation."""
import pathlib

from suit_generator.suit.types.common import SuitKeyValueUnnamed, SuitTstr, Metadata, SuitHex


class SuitIntegratedPayloadMap(SuitKeyValueUnnamed):
    """Representation of SUIT payloads."""

    _metadata = Metadata(map={SuitTstr: SuitHex})

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        ret = {}
        for k, v in obj.items():
            for c_k, c_v in cls._metadata.map.items():
                try:
                    if pathlib.Path.is_file(pathlib.Path(v)):
                        with open(v, "rb") as fh:
                            data = fh.read().hex().upper()
                            key = c_k.from_obj(k)
                            ret[k] = (key, c_v.from_obj(data))
                            break
                except ValueError:
                    pass
            else:
                raise ValueError(f"Unable to parse key-value pair: {k}: {v}")
        return cls(ret)
