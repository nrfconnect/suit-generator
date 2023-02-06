#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Common SUIT item types.

Code inspired by/based on https://github.com/tomchy/suit-composer.
"""
from __future__ import annotations
import cbor2
from dataclasses import dataclass
from suit_generator.logger import log_call


@dataclass
class Tag:
    """Tag metadata."""

    value: int = None
    name: str = None


@dataclass
class Metadata:
    """SUIT items metadata."""

    children: list | None = None
    tag: Tag | None = None
    map: dict | None = None


def check_input_type(input_type, msg):
    """Decorate method to handle wrong argument type."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            if (args[1] is not None) and (not isinstance(args[1], input_type)):
                raise ValueError(msg)
            return func(*args, **kwargs)

        return wrapper

    return decorator


class SuitObject:
    """SUIT basic object."""

    value = None
    metadata = None

    def __init__(self, value):
        """Initialize object."""
        self.value = value

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        return cls(obj)

    def to_obj(self):
        """Dump SUIT representation to object."""
        return self.value

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        return cls(cbor2.loads(cbstr))

    def to_cbor(self):
        """Dump SUIT representation to cbor."""
        return cbor2.dumps(self.value)

    @staticmethod
    def ensure_cbor(data):
        """Ensure data cbor encoded."""
        return cbor2.dumps(data) if not isinstance(data, bytes) else data


class SuitEnum(SuitObject):
    """Representation of SUIT enum."""

    def __init__(self, value):
        """Initialize object."""
        if value is not None:
            if value not in [i.name for i in self.metadata.children]:
                raise ValueError(f"Unknown key for enum: {value}")
        super().__init__(value)

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        if child := [i for i in cls.metadata.children if i.id == cbor2.loads(cbstr)]:
            return cls(child[0].name)
        else:
            raise ValueError(f"Key {cbstr.hex()} not found")


class SuitNull(SuitObject):
    """Representation of null type."""

    def __init__(self, value):
        """Initialize object."""
        if value is not None:
            raise ValueError(f"Unable to create NULL from {value}")
        super().__init__(value)


class SuitInt(SuitObject):
    """Representation of int type."""

    @check_input_type(int, "Wrong input type!")
    def __init__(self, value):
        """Initialize object."""
        super().__init__(value)


class SuitUint(SuitInt):
    """Representation of unsigned int type."""

    @check_input_type(int, "Wrong input type!")
    def __init__(self, value):
        """Initialize object."""
        if value < 0:
            raise ValueError(f"Unable to create unsigned int from {value}")
        super().__init__(value)


class SuitHex(SuitObject):
    """Representation of hex type."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        return cls(cbstr.hex())


class SuitBool(SuitObject):
    """Representation of boolean type."""

    @check_input_type(bool, "Wrong input type!")
    def __init__(self, value):
        """Initialize object."""
        super().__init__(value)


# TODO: maybe is worth to remove suit union at all and add configuration, required occurrences etc. as a metadata
#   to simplify methods and internal structures?
class SuitUnion(SuitObject):
    """Representation of different sub-items stored in the same location (alternatives)."""

    @classmethod
    @check_input_type(bytes, "Wrong input type!")
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed object."""
        for child in cls.metadata.children:
            try:
                value = child.from_cbor(cbstr)
                break
            except ValueError:
                pass
        else:
            # TODO: exception shall be raised after development or behaviour shall be configurable?
            #  maybe even on the fly? what in case user would like to debug corrupted envelope - shall we allow to
            #  restore suit structure and skip broken/missing fields?
            value = None
        return cls(value)


class SuitTupleNamed(SuitObject):
    """Representation of named tuple."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        if not isinstance(value_list := cbor2.loads(cbstr), list):
            raise ValueError(f"Expected list with values, received: {value_list}")

        children = list(cls.metadata.map.values())
        children.reverse()
        value = [children.pop().from_cbor(cls.ensure_cbor(v)) for v in value_list]
        return cls(value)


class SuitKeyValue(SuitObject):
    """Representation of key value items."""

    @classmethod
    def _get_method_and_name(cls, key):
        metadata_entry = [[k, v] for k, v in cls.metadata.map.items() if k.id == key]
        return (metadata_entry[0][0], metadata_entry[0][1]) if metadata_entry else None

    @classmethod
    @log_call
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        value = {}
        kv_dict = cbor2.loads(cbstr)
        if not isinstance(kv_dict, dict):
            raise ValueError(f"Expected key-value storage, received: {kv_dict}")
        for k, v in kv_dict.items():
            if not (child := cls._get_method_and_name(k)):
                # TODO: exception shall be raised after development or behaviour shall be configurable
                continue
            value[child[0]] = child[1].from_cbor(cls.ensure_cbor(v))
        return cls(value)


class SuitKeyValueUnnamed(SuitObject):
    """Representation of unnamed key value."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        ret = {}
        kv_dict = cbor2.loads(cbstr)
        # TODO: shall be moved to cbor loader to simplify methods body
        if not isinstance(kv_dict, dict):
            raise ValueError(f"Expected key-value storage, received: {kv_dict}")
        for k, v in kv_dict.items():
            for c_k, c_v in cls.metadata.map.items():
                try:
                    key = c_k.from_cbor(cbor2.dumps(k))
                    value = c_v.from_cbor(cbor2.dumps(v))
                    dict_key = key.to_obj()
                    ret[dict_key] = (key, value)
                    break
                except ValueError:
                    pass
            else:
                raise ValueError(f"Unable to parse key-value pair: {k}: {v}")
        return cls(ret)


class SuitKeyValueTupple(SuitKeyValue):
    """Representation of key value tupple."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        value = {}
        k, v = cbor2.loads(cbstr)

        if not (child := cls._get_method_and_name(k)):
            raise ValueError(f"Unknown parameter: {k}")

        value[child[0]] = child[1].from_cbor(cls.ensure_cbor(v))
        return cls(value)


class SuitTstr(SuitObject):
    """Representation of text string."""

    @check_input_type(str, "Wrong input type!")
    def __init__(self, value):
        """Initialize object."""
        super().__init__(value)


class SuitBstr(SuitObject):
    """Representation of byte string."""

    @check_input_type(bytes, "Wrong input type!")
    def __init__(self, value):
        """Initialize object."""
        super().__init__(value)

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        return cbor2.loads(cbstr)


class SuitTag(SuitObject):
    """Representation of tag."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        cbor = cbor2.loads(cbstr)
        if cls.metadata.tag.value != cbor.tag:
            raise ValueError(f"CBOR tag not found in: {cbor}")
        return cls(cbor2.CBORTag(cbor.tag, cls.metadata.children[0].from_cbor(cbor2.dumps(cbor.value))))


class SuitList(SuitObject):
    """Representation of list."""

    _group = None

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        values = cbor2.loads(cbstr)
        if not isinstance(values, list):
            raise ValueError(f"Unable to construct list from: {values}")
        # TODO: to refactor or remove
        if cls._group is not None:
            values = [values[i : i + cls._group] for i in range(0, len(values), cls._group)]
        value = (
            [cls.metadata.children[0].from_cbor(cls.ensure_cbor(v)) for v in values] if cls.metadata.children else None
        )
        return cls(tuple(value))


class SuitListUint(SuitList):
    """Representation of uint list."""

    metadata = Metadata(children=[SuitInt])


class SuitBitfield(SuitObject):
    """Representation of bit field."""

    _bit_class = SuitUint
    _bit_length = 32

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        value = []
        bitsum = 0
        bitval = cbor2.loads(cbstr)
        for bit in range(cls._bit_length):
            bitmask = 1 << bit
            if bitval & bitmask:
                bitsum += bitmask
                bit_obj = cls._bit_class.from_cbor(cbor2.dumps(bitmask))
                value.append(bit_obj)
        if bitsum != bitval:
            raise ValueError(f"Unable to represent the value {bitval} using {cls._bit_length} bits.")
        return cls(value)
