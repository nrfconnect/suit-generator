#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""SUIT authentication elements representation.

Code inspired by/based on https://github.com/tomchy/suit-composer.
"""
from suit_generator.suit.types.common import (
    Metadata,
    SuitNull,
    SuitEnum,
    SuitInt,
    SuitTstr,
    SuitHex,
    SuitUnion,
    SuitTupleNamed,
    SuitKeyValue,
    SuitBstr,
    SuitTag,
    Tag,
    cbstr,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from suit_generator.suit.types.keys import (
    suit_cose_algorithm_id,
    suit_cose_key_id,
    suit_issuer,
    suit_subject,
    suit_audience,
    suit_expiration_time,
    suit_not_before,
    suit_issued_at,
    suit_cw_id,
    cose_alg_sha_256,
    cose_alg_shake128,
    cose_alg_sha_384,
    cose_alg_sha_512,
    cose_alg_shake256,
    cose_alg_es_256,
)


class SuitHash:
    """Representation of SUIT hash."""

    _hash_func = {
        "cose-alg-sha-256": hashes.SHA256(),
        "cose-alg-shake128": hashes.SHAKE128(16),
        "cose-alg-sha-384": hashes.SHA384(),
        "cose-alg-sha-512": hashes.SHA512(),
        "cose-alg-shake256": hashes.SHAKE256(32),
    }

    def __init__(self, hash_name):
        """Initialize object."""
        if hash_name not in self._hash_func.keys():
            raise ValueError(f"Unsupported hash algorithm: {hash_name}")
        self._hash_name = hash_name

    def hash(self, bstr):
        """Compute hash value."""
        func = hashes.Hash(self._hash_func[self._hash_name], backend=default_backend())
        func.update(bstr)
        return func.finalize().hex()


class SuitCoseHashAlg(SuitEnum):
    """Representation of COSE hash algorithm map."""

    _metadata = Metadata(
        children=[
            cose_alg_sha_256,
            cose_alg_shake128,
            cose_alg_sha_384,
            cose_alg_sha_512,
            cose_alg_shake256,
        ]
    )


class SuitDigestBytes(SuitHex):
    """Representation of SUIT digests bytes."""

    pass


class SuitDigestRaw(SuitTupleNamed):
    """Representation of SUIT digests bytes in raw form."""

    _metadata = Metadata(
        map={
            "suit-digest-algorithm-id": SuitCoseHashAlg,
            "suit-digest-bytes": SuitDigestBytes,
        }
    )


class SuitDigestExt:
    """Representation of SUIT digest ext."""

    @classmethod
    def from_cbor(cls, cbstr):
        """Restore SUIT representation from passed CBOR string."""
        raise ValueError("The extended digest class can be used only with objects")

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        if not isinstance(obj, dict):
            raise ValueError(f"Expected dict, received: {obj}")
        if "suit-digest-bytes" not in obj.keys():
            obj["suit-digest-bytes"] = ""

        elif isinstance(obj["suit-digest-bytes"], dict):
            digest_dict = obj["suit-digest-bytes"]

            if "file" in digest_dict.keys():
                hfunc = SuitHash(obj["suit-digest-algorithm-id"])
                with open(digest_dict["file"], "rb") as fd:
                    obj["suit-digest-bytes"] = hfunc.hash(fd.read())

            elif "raw" in digest_dict.keys():
                obj["suit-digest-bytes"] = digest_dict["raw"]

            else:
                raise ValueError(f"Unable to calculate digest from: {digest_dict}")

        return SuitDigestRaw.from_obj(obj)


class SuitDigest(SuitUnion):
    """Representation of SUIT digest."""

    _metadata = Metadata(children=[SuitDigestRaw, SuitDigestExt])


class SuitcoseSignAlg(SuitEnum):
    """Representation of SUIT COSE sign algorithm."""

    _metadata = Metadata(children=[cose_alg_es_256])


class SuitHeaderMap(SuitKeyValue):
    """Representation of SUIT header map."""

    _metadata = Metadata(
        map={
            suit_cose_algorithm_id: SuitcoseSignAlg,
            suit_cose_key_id: SuitBstr,
        }
    )


class SuitHeaderData(SuitUnion):
    """Abstract element to define possible sub-elements."""

    _metadata = Metadata(
        children=[
            SuitKeyValue,
            SuitHeaderMap,
        ]
    )


class SuitCwtPayload(SuitKeyValue):
    """Representation of CBOR Web Token."""

    _parameters = {
        suit_issuer: SuitTstr,
        suit_subject: SuitTstr,
        suit_audience: SuitTstr,
        suit_expiration_time: SuitInt,
        suit_not_before: SuitInt,
        suit_issued_at: SuitInt,
        suit_cw_id: SuitBstr,
    }


class CoseSign1Payload(SuitUnion):
    """Representation of COSE_Sign1_payload item."""

    _metadata = Metadata(
        children=[
            SuitNull,
            SuitCwtPayload,
        ]
    )


class CoseSign1(SuitTupleNamed):
    """Representation of COSE_Sign1 item."""

    _metadata = Metadata(
        map={
            "protected": SuitHeaderMap,
            "unprotected": SuitHeaderData,
            "payload": CoseSign1Payload,
            "signature": SuitBstr,
        }
    )


class CoseSign1Tagged(SuitTag):
    """Representation of COSE_Sign1_Tagged item."""

    _metadata = Metadata(children=[CoseSign1], tag=Tag(18, "COSE_Sign1_Tagged"))


class SuitAuthenticationBlock(SuitUnion):
    """Representation of SuitAuthentication_Block item."""

    _metadata = Metadata(children=[CoseSign1Tagged])


class SuitAuthenticationUnsigned(SuitTupleNamed):
    """Representation of SuitAuthentication item."""

    _metadata = Metadata(map={"SuitDigest": cbstr(SuitDigest)})


# class SuitAuthentication(SuitUnion):
#     """Abstract element to define possible sub-elements."""
#
#     _metadata = Metadata(children=[SuitDigest])


class SuitAuthentication(SuitUnion):
    """Abstract element to define possible sub-elements."""

    _metadata = Metadata(children=[SuitAuthenticationUnsigned])


class SuitAuthenticationWrapper(SuitTupleNamed):
    """Representation of SUIT authentication wrapper."""

    _metadata = Metadata(map={"SuitAuthentication": SuitAuthentication})
