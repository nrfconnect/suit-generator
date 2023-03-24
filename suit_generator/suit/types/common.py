#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Common SUIT item types.

Code inspired by/based on https://github.com/tomchy/suit-composer.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from suit_generator.logger import log_call
import functools
import cbor2
import binascii
from suit_generator.suit.types.keys import suit_integrated_payloads, suit_integrated_dependencies


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
    embedded: list | None = None


def cbstr(cls):
    """Decorate method to dump value as cbor.

    Decorator might be used to cast SUIT internal element to cbor encoded in the output byte string.

    For example, CDDL might contain following entries:
    SUIT_Manifest = {
      suit-manifest-version         => 1,
      suit-manifest-sequence-number => uint,
      suit-common                   => bstr .cbor SUIT_Common,
      ? suit-reference-uri          => tstr,
      SUIT_Severable_Members_Choice,
      SUIT_Unseverable_Members,
    }

    according to the specification above suit-common shall be stored as cbor byte string - cbor decorator might be
    used here to avoid creation of two different internal representations one stored in plain form and one store
    in cbor encoded form:
        suit_common: cbstr(SuitCommon)

    """

    class Cbstr(cls):
        """Decorator implementation."""

        def __init__(self, *args, **kwargs):
            """Init object.

            Init object and wrap to look like original cls.
            """
            functools.update_wrapper(Cbstr, cls, updated=[])
            super().__init__(*args, **kwargs)

        def to_cbor(self):
            """Dump to cbor encoded byte string."""
            return cbor2.dumps(super().to_cbor())

    return Cbstr


def bchar(cls):
    """Decorate method to dump value as bytes."""

    class Bchar(cls):
        """Decorator implementation."""

        def __init__(self, *args, **kwargs):
            """Init object.

            Init object and wrap to look like original cls.
            """
            functools.update_wrapper(Bchar, cls, updated=[])
            super().__init__(*args, **kwargs)

        @classmethod
        def from_cbor(cls, cbstr):
            if (not isinstance(cbstr, bytes)) or (len(cbstr) != 1):
                raise ValueError(f"Unable to create component type from {cbstr}")
            if (ret := cbstr.decode()).isalpha():
                return cls(ret)
            else:
                raise ValueError(f"Not proper character {cbstr}")

        def to_cbor(self):
            """Dump to bytes."""
            return cbor2.dumps(self.value.encode())

    return Bchar


class SuitObject:
    """SUIT basic object."""

    _metadata = None

    def __init__(self, value):
        """Initialize object."""
        setattr(self, self.__class__.__name__, value)

    @property
    def value(self):
        """Link to dynamically created SUIT attribute."""
        for item in self.__dict__:
            if "Suit" in item:
                return getattr(self, item)
        else:
            raise ValueError("Not possible to get value!")

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
            if value not in [i.name for i in self._metadata.children]:
                raise ValueError(f"Unknown key for enum: {value}")
        super().__init__(value)

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        if child := [i for i in cls._metadata.children if i.id == cbor2.loads(cbstr)]:
            return cls(child[0].name)
        else:
            raise ValueError(f"Key {cbstr.hex()} not found")

    def to_cbor(self):
        """Dump SUIT representation to cbor encoded bytes."""
        if child := [i for i in self._metadata.children if i.name == self.value]:
            return cbor2.dumps(child[0].id)
        else:
            raise Exception(f"not possible to create cbor for name {self.value}")


class SuitNull(SuitObject):
    """Representation of null type."""

    def __init__(self, value):
        """Initialize object."""
        if value is not None:
            raise ValueError(f"Unable to create NULL from {value}")
        super().__init__(value)


class SuitInt(SuitObject):
    """Representation of int type."""

    def __init__(self, value):
        """Init object."""
        if (value is not None) and (not isinstance(value, int)):
            raise ValueError(f"Unable to create int from {value}")
        super().__init__(value)


class SuitUint(SuitInt):
    """Representation of unsigned int type."""

    def __init__(self, value):
        """Init object."""
        if (value is not None) and ((not isinstance(value, int)) or (value < 0)):
            raise ValueError(f"Unable to create unsigned int from {value}")
        super().__init__(value)


class SuitBool(SuitObject):
    """Representation of boolean type."""

    def __init__(self, value):
        """Init object."""
        if (value is not None) and (not isinstance(value, bool)):
            raise ValueError(f"Unable to create bool from {value}")
        super().__init__(value)


# TODO: maybe is worth to remove suit union at all and add configuration, required occurrences etc. as a metadata
#   to simplify methods and internal structures?
class SuitUnion(SuitObject):
    """Representation of different sub-items stored in the same location (alternatives)."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed object."""
        for child in cls._metadata.children:
            try:
                value = child.from_cbor(cbstr)
                break
            except ValueError:
                pass
        else:
            raise ValueError("Not possible ")
        return cls(value)

    def to_cbor(self):
        """Dump SUIT representation to cbor encoded bytes."""
        return self.value.to_cbor()

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        value = None
        for c in cls._metadata.children:
            try:
                value = c.from_obj(obj)
                break
            except ValueError:
                pass
        if value is None:
            raise ValueError(f"Unable to parse input: {obj}")
        return cls(value)

    def to_obj(self):
        """Dump SUIT representation to object."""
        if isinstance(self.value, str):
            return self.value
        return self.value.to_obj()


class SuitTupleNamed(SuitObject):
    """Representation of named tuple."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        if not isinstance(value_list := cbor2.loads(cbstr), list):
            raise ValueError(f"Expected list with values, received: {value_list}")

        children = list(cls._metadata.map.values())
        children.reverse()
        value = [children.pop().from_cbor(cls.ensure_cbor(v)) for v in value_list]
        return cls(value)

    def to_cbor(self):
        """Dump SUIT representation to cbor encoded bytes."""
        data = []
        for v in self.value:
            data.append(cbor2.loads(v.to_cbor()))
        return cbor2.dumps(data)

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        value = []
        if not isinstance(obj, dict):
            raise ValueError(f"Expected dict, received: {obj}")
        for k, c in cls._metadata.map.items():
            if k not in obj.keys():
                raise ValueError(f"Incomplete list. Missing: {k}")
            else:
                value.append(c.from_obj(obj[k]))
        return cls(value)

    def to_obj(self):
        """Dump SUIT representation to object."""
        value = {}
        keys = [k for k, c in self._metadata.map.items()]
        keys.reverse()
        for v in self.value:
            value[keys.pop()] = v.to_obj()
        return value


class SuitKeyValue(SuitObject):
    """Representation of key value items."""

    @classmethod
    def _get_method_and_name(cls, key, attribute="id"):
        metadata_entry = [[k, v] for k, v in cls._metadata.map.items() if getattr(k, attribute) == key]
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
            if not (child := cls._get_method_and_name(k, "id")):
                for item in cls._metadata.embedded:
                    try:
                        value[item] = cls._metadata.map[item].from_cbor(cbor2.dumps({k: v}))
                    except ValueError:
                        pass
            else:
                value[child[0]] = child[1].from_cbor(cls.ensure_cbor(v))
        return cls(value)

    def to_cbor(self):
        """Dump SUIT representation to cbor encoded bytes."""
        data = {}
        for k, v in self.value.items():
            if k is suit_integrated_payloads or k is suit_integrated_dependencies:
                data.update(cbor2.loads(v.to_cbor()))
            else:
                data[k.id] = cbor2.loads(v.to_cbor())
        return cbor2.dumps(data)

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        value = {}
        if not isinstance(obj, dict):
            raise ValueError(f"Unable to construct dict from: {obj}")
        for k, v in obj.items():
            if child := cls._get_method_and_name(k, "name"):
                value[child[0]] = child[1].from_obj(v)
            else:
                raise ValueError(f"Unknown parameter: {k}")
        return cls(value)

    def to_obj(self):
        """Dump SUIT representation to object."""
        obj = {}
        for k, v in self.value.items():
            if k in self._metadata.map.keys():
                key = k.name
                value = v.to_obj()
            else:
                key = k.to_obj()
                value = cbor2.loads(v.value)
            obj[key] = value
        return obj


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
            for c_k, c_v in cls._metadata.map.items():
                try:
                    key = c_k.from_cbor(cbor2.dumps(k))
                    # fixme: both if's could be removed at all
                    if isinstance(key, list):
                        key = tuple(key)
                    value = c_v.from_cbor(cls.ensure_cbor(v))
                    if isinstance(value, list):
                        value = tuple(value)
                    dict_key = key.to_obj()
                    if not isinstance(dict_key, str):
                        dict_key = json.dumps(dict_key)
                    ret[dict_key] = (key, value)
                    break
                except ValueError:
                    pass
            else:
                raise ValueError(f"Unable to parse key-value pair: {k}: {v}")
        return cls(ret)

    def to_cbor(self):
        """Dump SUIT representation to cbor encoded bytes."""
        obj = {}
        for k, v in self.value.items():
            key = cbor2.loads(v[0].to_cbor())
            if isinstance(key, list):
                key = tuple(key)
            obj[key] = cbor2.loads(v[1].to_cbor())
        return cbor2.dumps(obj)

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        ret = {}
        for k, v in obj.items():
            for c_k, c_v in cls._metadata.map.items():
                try:
                    try:
                        key = c_k.from_obj(json.loads(k))
                    except ValueError:
                        key = c_k.from_obj(k)
                    except json.decoder.JSONDecodeError:
                        key = c_k.from_obj(k)
                    ret[k] = (key, c_v.from_obj(v))
                    break
                except ValueError:
                    pass
            else:
                raise ValueError(f"Unable to parse key-value pair: {k}: {v}")
        return cls(ret)

    def to_obj(self):
        """Dump SUIT representation to object."""
        return {k:v[1].to_obj() for k, v in self.value.items()}


class SuitKeyValueTuple(SuitKeyValue):
    """Representation of key value tuple."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        value = {}
        k, v = cbor2.loads(cbstr)

        if not (child := cls._get_method_and_name(k)):
            raise ValueError(f"Unknown parameter: {k}")

        value[child[0]] = child[1].from_cbor(cls.ensure_cbor(v))
        return cls(value)

    def to_cbor(self):
        """Dump SUIT representation to cbor encoded bytes."""
        obj = []
        for k, v in self.value.items():
            key = k.id
            value = cbor2.loads(v.to_cbor())
            obj.append(key)
            obj.append(value)
        return cbor2.dumps(obj)


class SuitTstr(SuitObject):
    """Representation of text string."""

    def __init__(self, value):
        """Init object."""
        if (value is not None) and (not isinstance(value, str)):
            raise ValueError(f"Unable to create string from {value}")
        super().__init__(value)


class SuitBstr(SuitObject):
    """Representation of byte string."""

    def __init__(self, value):
        """Init object."""
        if (value is not None) and (not isinstance(value, bytes)):
            raise ValueError(f"Unable to create bytes from {value}")
        super().__init__(value)

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        return cls(cbstr)

    def to_cbor(self):
        """Dump SUIT representation to cbor encoded bytes."""
        return cbor2.dumps(self.value)

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        if not isinstance(obj, str):
            raise ValueError(f"Expected hex string, received: {obj}")
        return cls(binascii.a2b_hex(obj))

    def to_obj(self):
        """Dump SUIT representation to object."""
        return self.value.hex()


class SuitHex(SuitBstr):
    """Representation of hex type."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        return cls(cbstr)


class SuitTag(SuitObject):
    """Representation of tag."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR."""
        cbor = cbor2.loads(cbstr)
        if cls._metadata.tag.value != cbor.tag:
            raise ValueError(f"CBOR tag not found in: {cbor}")
        return cls(cbor2.CBORTag(cbor.tag, cls._metadata.children[0].from_cbor(cbor2.dumps(cbor.value))))

    def to_cbor(self):
        """Dump SUIT representation to cbor encoded bytes."""
        return cbor2.dumps(cbor2.CBORTag(self._metadata.tag.value, cbor2.loads(self.value.value.to_cbor())))

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        if cls._metadata.tag.name not in obj.keys():
            raise ValueError(f"CBOR tag not found in: {obj}")
        return cls(
            cbor2.CBORTag(cls._metadata.tag.value, cls._metadata.children[0].from_obj(obj[cls._metadata.tag.name]))
        )

    def to_obj(self):
        """Dump SUIT representation to object."""
        return {self._metadata.tag.name: self.value.value.to_obj()}


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
            [cls._metadata.children[0].from_cbor(cls.ensure_cbor(v)) for v in values]
            if cls._metadata.children
            else None
        )
        return cls(tuple(value))

    def to_cbor(self):
        """Dump SUIT representation to cbor encoded bytes."""
        data = []
        for v in self.value:
            if self._group is not None:
                z = cbor2.loads(v.to_cbor())
                if isinstance(z, list):
                    z = tuple(z)
                data.extend(z)
            else:
                z = cbor2.loads(v.to_cbor())
                if isinstance(z, list):
                    z = tuple(z)
                data.append(z)
        return cbor2.dumps(data)

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        value = []
        for v in obj:
            value.append(cls._metadata.children[0].from_obj(v))
        return cls(tuple(value))

    def to_obj(self):
        """Dump SUIT representation to object."""
        return [v.to_obj() for v in self.value]


class SuitListUint(SuitList):
    """Representation of uint list."""

    _metadata = Metadata(children=[SuitInt])


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

    def to_cbor(self):
        """Dump SUIT representation to cbor encoded bytes."""
        value = 0
        for bit in self.value:
            value += cbor2.loads(bit.to_cbor())
        return cbor2.dumps(value)

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        value = []
        if not isinstance(obj, list):
            raise ValueError(f"Unable to parse bitlist: {obj}")
        for bit in obj:
            bit_obj = cls._bit_class.from_obj(bit)
            value.append(bit_obj)
        return cls(value)

    def to_obj(self):
        """Dump SUIT representation to object."""
        value = []
        for bit in self.value:
            value.append(bit.to_obj())
        return value
