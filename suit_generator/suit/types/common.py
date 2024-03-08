#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Common SUIT item types.

Code inspired by/based on https://github.com/tomchy/suit-composer.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import cast, Any
import functools
import binascii
import logging
import struct
import json
import yaml

import cbor2

from suit_generator.logger import log_call
from suit_generator.suit.types.keys import suit_integrated_payloads, suit_integrated_dependencies
from suit_generator.exceptions import GeneratorError, SUITError

logger = logging.getLogger(__name__)


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

        def __init__(self, *args, **kwargs) -> None:
            """Init object.

            Init object and wrap to look like original cls.
            """
            functools.update_wrapper(Cbstr, cls, updated=[])
            super().__init__(*args, **kwargs)

        def to_cbor(self) -> bytes:
            """Dump to cbor encoded byte string."""
            return cbor2.dumps(super().to_cbor())

    return Cbstr


class PrettyPrintHelperMixin:
    """Mixin class providing helper methods for pretty printing objects for debugging purposes."""

    @staticmethod
    def pretty_format_obj(obj: object) -> None:
        """Convert the passed object into a human-readable debug string using YAML format."""
        return f"\n{yaml.dump(obj)}\n"


class SuitObject(PrettyPrintHelperMixin):
    """SUIT basic object."""

    _metadata = None

    def __init__(self, value: Any) -> None:
        """Initialize object."""
        setattr(self, self.__class__.__name__, value)

    @staticmethod
    def decode_cbor_length(subtype: int, data: bytes, allow_indefinite: bool = False) -> int | None:
        """Decode cbor object length.

        https://github.com/agronholm/cbor2/blob/master/cbor2/_decoder.py#L258-L272
        """
        try:
            if subtype < 24:
                return subtype
            elif subtype == 24:
                return data[0]
            elif subtype == 25:
                return cast(int, struct.unpack(">H", data[:2])[0])
            elif subtype == 26:
                return cast(int, struct.unpack(">L", data[:4])[0])
            elif subtype == 27:
                return cast(int, struct.unpack(">Q", data[:8])[0])
            elif subtype == 31 and allow_indefinite:
                return None
            else:
                raise Exception("unknown unsigned integer subtype 0x%x" % subtype)
        except Exception:
            raise cbor2.CBORDecodeError("Not possible to detect cbor length!")

    @staticmethod
    def validate_cbor(cbstr: bytes) -> None:
        """Validate cbor.

        NCSDK-24195, https://github.com/agronholm/cbor2/issues/186 - due to bug in cbor2 package verify if cbstr
        does not contain data which will cause that cbor2 library will request huge amount of memory.
        """
        requested_memory_len = None
        cbor_item_type = cbstr[0] >> 5
        cbor_item_count = cbstr[0] & 31
        # fixme: do not validate CBORTag length
        if 1 < cbor_item_type < 6 and 23 < cbor_item_count < 28:
            try:
                # Check only for long field encoding (String, Items, Tag) with short count in range 24 - 27
                requested_memory_len = SuitObject.decode_cbor_length(cbor_item_count, cbstr[1:])
            except cbor2.CBORDecodeError:
                # Exception means that it is not possible to extract size which automatically does not mean
                # that this value should not be parsed by cbor2 package
                pass
        if requested_memory_len and requested_memory_len > len(cbstr):
            raise ValueError(
                f"Requested memory for cbstr parsed object {requested_memory_len} "
                f"is greater than cbstr length itself: {len(cbstr)}"
            )

    @staticmethod
    def deserialize_cbor(cbstr: bytes) -> Any:
        """Verify and deserialize cbor object."""
        # Ensure that cbor2.loads() will not consume all the available memory
        SuitObject.validate_cbor(cbstr)
        try:
            return cbor2.loads(cbstr)
        except Exception:
            # Catch all exceptions since cbor2.loads raises a lot of different exceptions for invalid data:
            #   Payload in hex -> Exception type
            #   c11b9b9b9b0000000000 -> OverflowError
            #   c11b1616161616161616161616161616 -> OSError
            #   95393b7b7b7b7b7b7b7b7b7b7b7b7b7b -> MemoryError
            #   d8250010600000006010000000000000 -> TypeError
            #   d81e84ffffffff -> SystemError
            #   d8234129 -> re.error
            raise ValueError("Cannot deserialize data!")

    @staticmethod
    def serialize_cbor(obj: Any) -> bytes:
        """Serialize cbor object."""
        try:
            return cbor2.dumps(obj)
        except Exception:
            raise ValueError("Cannot serialize data!")

    @property
    def value(self) -> Any:
        """Link to dynamically created SUIT attribute."""
        for item in self.__dict__:
            if "Suit" in item or "Cose" in item:
                return getattr(self, item)
        else:
            raise ValueError("Not possible to get value!")

    @value.setter
    def value(self, value: Any) -> Any:
        """Link to dynamically created SUIT attribute."""
        for item in self.__dict__:
            if "Suit" in item or "Cose" in item:
                return setattr(self, item, value)
        else:
            raise ValueError("Not possible to get value!")

    @classmethod
    @log_call
    def from_obj(cls, obj: Any) -> SuitObject:
        """Restore SUIT representation from passed object."""
        return cls(obj)

    @log_call
    def to_obj(self) -> Any:
        """Dump SUIT representation to object."""
        return self.value

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitObject:
        """Restore SUIT representation from passed CBOR."""
        return cls(cls.deserialize_cbor(cbstr))

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor."""
        return self.serialize_cbor(self.value)

    @classmethod
    def ensure_cbor(cls, data: Any) -> bytes:
        """Ensure data cbor encoded."""
        return cls.serialize_cbor(data) if not isinstance(data, bytes) else data


class SuitBchar(SuitObject):
    """Representation of a single-character encoded as raw bytes."""

    def __init__(self, value: None | str) -> None:
        """Initialize object."""
        if value is not None:
            if (not isinstance(value, str)) or (len(value) != 1):
                raise ValueError(f"Unable to create single-byte type from: {value}")
        super().__init__(value)

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitBchar:
        """Restore SUIT representation from passed CBOR."""
        if (not isinstance(cbstr, bytes)) or (len(cbstr) != 1):
            raise ValueError(f"Unable to create component type from {cbstr}")
        if (ret := cbstr.decode()).isalpha():
            return cls(ret)
        else:
            raise ValueError(f"Not proper character {cbstr}")

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        return self.serialize_cbor(self.value.encode())


class SuitEnum(SuitObject):
    """Representation of SUIT enum."""

    def __init__(self, value: str) -> None:
        """Initialize object."""
        if value is not None:
            if value not in [i.name for i in self._metadata.children]:
                raise ValueError(f"Unknown key for enum: {value}")
        super().__init__(value)

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitEnum:
        """Restore SUIT representation from passed CBOR."""
        if child := [i for i in cls._metadata.children if i.id == cls.deserialize_cbor(cbstr)]:
            return cls(child[0].name)
        else:
            raise ValueError(f"Key {cbstr.hex()} not found")

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        if child := [i for i in self._metadata.children if i.name == self.value]:
            return self.serialize_cbor(child[0].id)
        else:
            raise Exception(f"not possible to create cbor for name {self.value}")


class SuitNull(SuitObject):
    """Representation of null type."""

    def __init__(self, value: Any) -> None:
        """Initialize object."""
        if value is not None:
            raise ValueError(f"Unable to create NULL from {value}")
        super().__init__(value)


class SuitInt(SuitObject):
    """Representation of int type."""

    def __init__(self, value: int) -> None:
        """Init object."""
        if (value is not None) and (not isinstance(value, int)):
            raise ValueError(f"Unable to create int from {value}")
        super().__init__(value)


class SuitUint(SuitInt):
    """Representation of unsigned int type."""

    def __init__(self, value: int) -> None:
        """Init object."""
        if (value is not None) and ((not isinstance(value, int)) or (value < 0)):
            raise ValueError(f"Unable to create unsigned int from {value}")
        super().__init__(value)


class SuitBool(SuitObject):
    """Representation of boolean type."""

    def __init__(self, value: bool) -> None:
        """Init object."""
        if (value is not None) and (not isinstance(value, bool)):
            raise ValueError(f"Unable to create bool from {value}")
        super().__init__(value)


class SuitUnion(SuitObject):
    """Representation of different sub-items stored in the same location (alternatives)."""

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitUnion:
        """Restore SUIT representation from passed object."""
        for child in cls._metadata.children:
            try:
                value = child.from_cbor(cbstr)
                break
            except ValueError:
                pass
        else:
            raise ValueError("Not possible to deserialize data")
        return cls(value)

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        return self.value.to_cbor()

    @classmethod
    @log_call
    def from_obj(cls, obj: Any) -> SuitUnion:
        """Restore SUIT representation from passed object."""
        value = None
        for c in cls._metadata.children:
            try:
                value = c.from_obj(obj)
                break
            except ValueError:
                pass
        if value is None:
            raise ValueError(f"{cls.__name__}: Unable to parse input: {cls.pretty_format_obj(obj)}")
        return cls(value)

    @log_call
    def to_obj(self):
        """Dump SUIT representation to object."""
        return self.value if isinstance(self.value, str) else self.value.to_obj()


class SuitTupleNamed(SuitObject):
    """Representation of named tuple."""

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitTupleNamed:
        """Restore SUIT representation from passed CBOR."""
        if not isinstance(value_list := cls.deserialize_cbor(cbstr), list):
            raise ValueError(f"Expected list with values, received: {value_list}")

        # children = list(cls._metadata.map.values())
        children = cls._metadata.map.items()
        value = []
        index = 0
        for child in children:
            key, method = child
            if key.endswith("*"):
                while True:
                    try:
                        value.append(method.from_cbor(cls.ensure_cbor(value_list[index])))
                        index += 1
                    except (ValueError, IndexError):
                        # ValueError if not possible to parse by current child so switch to next
                        # IndexError end of the list
                        break
            else:
                value.append(method.from_cbor(cls.ensure_cbor(value_list[index])))
                index += 1
        return cls(value)

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        data = []
        for v in self.value:
            data.append(self.deserialize_cbor(v.to_cbor()))
        return self.serialize_cbor(data)

    @classmethod
    @log_call
    def from_obj(cls, obj: dict) -> SuitTupleNamed:
        """Restore SUIT representation from passed object."""
        value = []
        if not isinstance(obj, dict):
            raise ValueError(f"{cls.__name__}: Expected dict, received: {type(obj)} for:{cls.pretty_format_obj(obj)}")
        for k, c in cls._metadata.map.items():
            if k in obj.keys():
                value.append(c.from_obj(obj[k]))
            elif k.endswith("*"):
                for sub_key in [i for i in obj.keys() if i.startswith(k.replace("*", ""))]:
                    value.append(c.from_obj(obj[sub_key]))
            else:
                raise ValueError(f"Incomplete list. Missing: {k}")
        return cls(value)

    @log_call
    def to_obj(self) -> dict:
        """Dump SUIT representation to object."""
        value = {}
        keys = list(self._metadata.map.keys())
        if len([i for i in keys[:-1] if "*" in i]) > 0:
            raise GeneratorError("Only last element can be defined in the metadata as dynamic(*)")
        dynamic_element = keys[-1] if "*" in keys[-1] else None
        keys.reverse()
        multiple_elements_index = 1
        for v in self.value:
            if len(keys) > 0:
                key = keys.pop().replace("*", str(multiple_elements_index))
            elif dynamic_element is not None:
                multiple_elements_index += 1
                key = dynamic_element.replace("*", str(multiple_elements_index))
            else:
                raise GeneratorError("Unable to parse input object - too many elements")
            value[key] = v.to_obj()
        return value


class SuitKeyValue(SuitObject):
    """Representation of key value items."""

    @classmethod
    def _get_method_and_name(cls, key, attribute="id"):
        metadata_entry = [[k, v] for k, v in cls._metadata.map.items() if getattr(k, attribute) == key]
        return (metadata_entry[0][0], metadata_entry[0][1]) if metadata_entry else None

    @classmethod
    @log_call
    def from_cbor(cls, cbstr: bytes) -> SuitKeyValue:
        """Restore SUIT representation from passed CBOR."""
        value = {}
        kv_dict = cls.deserialize_cbor(cbstr)
        if not isinstance(kv_dict, dict):
            raise ValueError(f"Expected key-value storage, received: {kv_dict}")
        for k, v in kv_dict.items():
            if not (child := cls._get_method_and_name(k, "id")):
                for item in cls._metadata.embedded:
                    try:
                        try:
                            # check payload content
                            from suit_generator.suit.envelope import SuitEnvelopeTaggedSimplified

                            SuitEnvelopeTaggedSimplified.from_cbor(v)
                            item = suit_integrated_dependencies
                        except Exception:
                            pass

                        if item not in cls._metadata.map:
                            raise ValueError(f"Impossible to create embedded element: {item}")

                        # TODO: refactoring required: workaround for multiple integrated payloads
                        if item in value and (item is suit_integrated_payloads or item is suit_integrated_dependencies):
                            value[item].SuitIntegratedPayloadMap = {
                                **value[item].SuitIntegratedPayloadMap,
                                **cls._metadata.map[item]
                                .from_cbor(cls.serialize_cbor({k: v}))
                                .SuitIntegratedPayloadMap,
                            }
                        else:
                            value[item] = cls._metadata.map[item].from_cbor(cls.serialize_cbor({k: v}))
                    except ValueError:
                        logger.warning(f"Not possible to deserialize data for {k}")
            else:
                value[child[0]] = child[1].from_cbor(cls.ensure_cbor(v))
        return cls(value)

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        data = {}
        for k, v in self.value.items():
            if k is suit_integrated_payloads or k is suit_integrated_dependencies:
                data.update(self.deserialize_cbor(v.to_cbor()))
            else:
                data[k.id] = self.deserialize_cbor(v.to_cbor())
        return self.serialize_cbor(data)

    @classmethod
    @log_call
    def from_obj(cls, obj: dict) -> SuitKeyValue:
        """Restore SUIT representation from passed object."""
        value = {}
        if not isinstance(obj, dict):
            raise ValueError(f"{cls.__name__} Expected dict, received: {type(obj)} for:{cls.pretty_format_obj(obj)}")
        for k, v in obj.items():
            if child := cls._get_method_and_name(k, "name"):
                value[child[0]] = child[1].from_obj(v)
            else:
                raise ValueError(f"Unknown parameter: {k}")
        return cls(value)

    @log_call
    def to_obj(self) -> dict:
        """Dump SUIT representation to object."""
        obj = {}
        for k, v in self.value.items():
            if k in self._metadata.map.keys():
                key = k.name
                value = v.to_obj()
            else:
                key = k.to_obj()
                value = self.deserialize_cbor(v.value)
            obj[key] = value
        return obj


class SuitKeyValueUnnamed(SuitObject):
    """Representation of unnamed key value."""

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitKeyValueUnnamed:
        """Restore SUIT representation from passed CBOR."""
        ret = {}
        kv_dict = cls.deserialize_cbor(cbstr)
        # TODO: shall be moved to cbor loader to simplify methods body
        if not isinstance(kv_dict, dict):
            raise ValueError(f"Expected key-value storage, received: {kv_dict}")
        for k, v in kv_dict.items():
            for c_k, c_v in cls._metadata.map.items():
                try:
                    key = c_k.from_cbor(cls.serialize_cbor(k))
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

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        obj = {}
        for k, v in self.value.items():
            key = self.deserialize_cbor(v[0].to_cbor())
            if isinstance(key, list):
                key = tuple(key)
            obj[key] = self.deserialize_cbor(v[1].to_cbor())
        return self.serialize_cbor(obj)

    @classmethod
    @log_call
    def from_obj(cls, obj: dict) -> SuitKeyValueUnnamed:
        """Restore SUIT representation from passed object."""
        ret = {}
        for k, v in obj.items():
            for c_k, c_v in cls._metadata.map.items():
                try:
                    try:
                        key = c_k.from_obj(json.loads(k))
                    except ValueError:
                        key = c_k.from_obj(k)
                    ret[k] = (key, c_v.from_obj(v))
                    break
                except ValueError:
                    pass
            else:
                raise ValueError(
                    f"{cls.__name__}: Unable to parse key-value pair: {k}: {v} for:{cls.pretty_format_obj(obj)}"
                )
        return cls(ret)

    @log_call
    def to_obj(self) -> dict:
        """Dump SUIT representation to object."""
        return {k: v[1].to_obj() for k, v in self.value.items()}


class SuitKeyValueTuple(SuitKeyValue):
    """Representation of key value tuple."""

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitKeyValueTuple:
        """Restore SUIT representation from passed CBOR."""
        value = {}
        cbor = cls.deserialize_cbor(cbstr)
        if not isinstance(cbor, list):
            raise ValueError(f"Unable to create Key/Value tuple from {cbstr}")
        k, v = cbor

        if not (child := cls._get_method_and_name(k)):
            raise ValueError(f"Unknown parameter: {k}")

        value[child[0]] = child[1].from_cbor(cls.ensure_cbor(v))
        return cls(value)

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        obj = []
        for k, v in self.value.items():
            key = k.id
            value = self.deserialize_cbor(v.to_cbor())
            obj.append(key)
            obj.append(value)
        return self.serialize_cbor(obj)


class SuitTstr(SuitObject):
    """Representation of text string."""

    def __init__(self, value: None | str) -> None:
        """Init object."""
        if (value is not None) and (not isinstance(value, str)):
            raise ValueError(f"Unable to create string from {value}")
        super().__init__(value)


class SuitBstr(SuitObject):
    """Representation of byte string."""

    def __init__(self, value: None | bytes) -> None:
        """Init object."""
        if (value is not None) and (not isinstance(value, bytes)):
            raise ValueError(f"Unable to create bytes from {value}")
        super().__init__(value)

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitBstr:
        """Restore SUIT representation from passed CBOR."""
        return cls(cbstr)

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        return self.serialize_cbor(self.value)

    @classmethod
    @log_call
    def from_obj(cls, obj: str) -> SuitBstr:
        """Restore SUIT representation from passed object."""
        if not isinstance(obj, str):
            raise ValueError(
                f"{cls.__name__}: Expected hex string, received: {type(obj)} for:{cls.pretty_format_obj(obj)}"
            )
        return cls(binascii.a2b_hex(obj))

    @log_call
    def to_obj(self) -> str:
        """Dump SUIT representation to object."""
        return self.value.hex()


class SuitHex(SuitBstr):
    """Representation of hex type."""

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitHex:
        """Restore SUIT representation from passed CBOR."""
        return cls(cbstr)


class SuitTag(SuitObject):
    """Representation of tag."""

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitTag:
        """Restore SUIT representation from passed CBOR."""
        cbor = cls.deserialize_cbor(cbstr)
        if not hasattr(cbor, "tag") or cls._metadata.tag.value != cbor.tag:
            raise SUITError(f"CBOR tag not found in: {cbor}")
        return cls(cbor2.CBORTag(cbor.tag, cls._metadata.children[0].from_cbor(cls.serialize_cbor(cbor.value))))

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        return self.serialize_cbor(
            cbor2.CBORTag(self._metadata.tag.value, self.deserialize_cbor(self.value.value.to_cbor()))
        )

    @classmethod
    @log_call
    def from_obj(cls, obj: dict) -> SuitTag:
        """Restore SUIT representation from passed object."""
        if not isinstance(obj, dict) or cls._metadata.tag.name not in obj.keys():
            raise ValueError(f"{cls.__name__}: CBOR tag not found in: {cls.pretty_format_obj(obj)}")

        return cls(
            cbor2.CBORTag(cls._metadata.tag.value, cls._metadata.children[0].from_obj(obj[cls._metadata.tag.name]))
        )

    @log_call
    def to_obj(self) -> dict:
        """Dump SUIT representation to object."""
        return {self._metadata.tag.name: self.value.value.to_obj()}


class SuitList(SuitObject):
    """Representation of list."""

    _group = None

    @classmethod
    def from_cbor(cls, cbstr: bytes) -> SuitList:
        """Restore SUIT representation from passed CBOR."""
        values = cls.deserialize_cbor(cbstr)
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

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        data = []
        for v in self.value:
            if self._group is not None:
                z = self.deserialize_cbor(v.to_cbor())
                if isinstance(z, list):
                    z = tuple(z)
                data.extend(z)
            else:
                z = self.deserialize_cbor(v.to_cbor())
                if isinstance(z, list):
                    z = tuple(z)
                data.append(z)
        return self.serialize_cbor(data)

    @classmethod
    @log_call
    def from_obj(cls, obj: list) -> SuitList:
        """Restore SUIT representation from passed object."""
        value = []
        for v in obj:
            value.append(cls._metadata.children[0].from_obj(v))
        return cls(tuple(value))

    @log_call
    def to_obj(self) -> list:
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
    def from_cbor(cls, cbstr: bytes) -> SuitBitfield:
        """Restore SUIT representation from passed CBOR."""
        value = []
        bitsum = 0
        bitval = cls.deserialize_cbor(cbstr)
        for bit in range(cls._bit_length):
            bitmask = 1 << bit
            if bitval & bitmask:
                bitsum += bitmask
                bit_obj = cls._bit_class.from_cbor(cls.serialize_cbor(bitmask))
                value.append(bit_obj)
        if bitsum != bitval:
            raise ValueError(f"Unable to represent the value {bitval} using {cls._bit_length} bits.")
        return cls(value)

    def to_cbor(self) -> bytes:
        """Dump SUIT representation to cbor encoded bytes."""
        value = 0
        for bit in self.value:
            value += self.deserialize_cbor(bit.to_cbor())
        return self.serialize_cbor(value)

    @classmethod
    @log_call
    def from_obj(cls, obj: list) -> SuitBitfield:
        """Restore SUIT representation from passed object."""
        value = []
        if not isinstance(obj, list):
            raise ValueError(f"{cls.__name__}: Unable to parse bitlist: {cls.pretty_format_obj(obj)}")
        for bit in obj:
            bit_obj = cls._bit_class.from_obj(bit)
            value.append(bit_obj)
        return cls(value)

    @log_call
    def to_obj(self) -> list:
        """Dump SUIT representation to object."""
        value = []
        for bit in self.value:
            value.append(bit.to_obj())
        return value
