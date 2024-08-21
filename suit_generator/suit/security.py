#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""SUIT authentication elements representation.

Code inspired by/based on https://github.com/tomchy/suit-composer.
"""
from suit_generator.suit.types.common import (
    Metadata,
    SuitNull,
    SuitEnum,
    SuitInt,
    SuitObject,
    SuitTstr,
    SuitHex,
    SuitUnion,
    SuitTupleNamed,
    SuitKeyValue,
    SuitList,
    SuitBstr,
    SuitEmptyBstr,
    SuitTag,
    Tag,
    cbstr,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from suit_generator.suit.types.keys import (
    suit_cose_algorithm_id,
    suit_cose_key_id,
    suit_cose_iv,
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
    cose_alg_es_384,
    cose_alg_es_521,
    cose_alg_eddsa,
    cose_alg_aes_gcm_128,
    cose_alg_aes_gcm_192,
    cose_alg_aes_gcm_256,
    cose_alg_a256kw,
    cose_alg_a192kw,
    cose_alg_a128kw,
    suit_digest_algorithm_id,
    suit_digest_bytes,
)
from suit_generator.suit.types.common import PrettyPrintHelperMixin
from suit_generator.logger import log_call


class SuitHash:
    """Representation of SUIT hash."""

    _hash_func = {
        "cose-alg-sha-256": hashes.SHA256(),
        "cose-alg-shake128": hashes.SHAKE128(16),
        "cose-alg-sha-384": hashes.SHA384(),
        "cose-alg-sha-512": hashes.SHA512(),
        "cose-alg-shake256": hashes.SHAKE256(32),
    }

    def __init__(self, hash_name: str) -> None:
        """Initialize object."""
        if hash_name not in self._hash_func.keys():
            raise ValueError(f"Unsupported hash algorithm: {hash_name}")
        self._hash_name = hash_name

    def hash(self, bstr: bytes) -> str:
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
            suit_digest_algorithm_id.name: SuitCoseHashAlg,
            suit_digest_bytes.name: SuitDigestBytes,
        }
    )


class SuitDigestExt(PrettyPrintHelperMixin):
    """Representation of SUIT digest ext."""

    @classmethod
    @log_call
    def from_cbor(cls, cbstr: bytes):
        """Restore SUIT representation from passed CBOR string."""
        raise ValueError("The extended digest class can be used only with objects")

    @classmethod
    def from_obj(cls, obj: dict) -> SuitDigestRaw:
        """Restore SUIT representation from passed object."""
        if not isinstance(obj, dict):
            raise ValueError(f"Expected dict, received: {obj}")
        # fixme: workaround to handle suit-text (SuitTextMap) in the manifest, without this workaround obj has
        #  additional suit-digest-bytes key which is not supported by suit-text (SuitTextMap)
        if not isinstance(obj, dict):
            raise ValueError(f"Expected dict, received: {type(obj)} for:\n{cls.pretty_format_obj(obj)}")
        if suit_digest_algorithm_id.name not in obj.keys():
            cls(SuitDigestRaw.from_obj(obj))
        if suit_digest_bytes.name not in obj.keys():
            obj[suit_digest_bytes.name] = ""

        elif isinstance(obj[suit_digest_bytes.name], dict):
            digest_dict = obj[suit_digest_bytes.name]

            if "file" in digest_dict.keys():
                hfunc = SuitHash(obj[suit_digest_algorithm_id.name])
                with open(digest_dict["file"], "rb") as fd:
                    obj[suit_digest_bytes.name] = hfunc.hash(fd.read())
            elif "envelope" in digest_dict.keys():
                from suit_generator.suit.envelope import SuitEnvelopeTagged

                if isinstance(digest_dict["envelope"], dict):
                    sub_envelope = SuitEnvelopeTagged.from_obj(digest_dict["envelope"])
                else:
                    with open(digest_dict["envelope"], "rb") as fh:
                        sub_envelope = SuitEnvelopeTagged.from_cbor(fh.read())
                sub_envelope.update_severable_digests()
                sub_envelope.update_digest()
                obj[suit_digest_bytes.name] = sub_envelope.get_manifest_digest(obj[suit_digest_algorithm_id.name]).hex()
            elif "raw" in digest_dict.keys():
                obj[suit_digest_bytes.name] = digest_dict["raw"]
            elif "file_direct" in digest_dict.keys():
                with open(digest_dict["file_direct"], "rb") as fd:
                    obj[suit_digest_bytes.name] = fd.read().hex()
            else:
                raise ValueError(f"Unable to calculate digest from: {digest_dict}")

        return SuitDigestRaw.from_obj(obj)


class SuitDigest(SuitUnion):
    """Representation of SUIT digest."""

    _metadata = Metadata(children=[SuitDigestRaw, SuitDigestExt])


class SuitcoseAlg(SuitEnum):
    """Representation of SUIT COSE sign algorithm."""

    _metadata = Metadata(
        children=[
            cose_alg_es_256,
            cose_alg_es_384,
            cose_alg_es_521,
            cose_alg_eddsa,
            cose_alg_aes_gcm_128,
            cose_alg_aes_gcm_192,
            cose_alg_aes_gcm_256,
            cose_alg_a256kw,
            cose_alg_a192kw,
            cose_alg_a128kw,
        ]
    )


class SuitcoseKeyId(SuitUnion):
    """Representation of a KEY ID item."""

    _metadata = Metadata(
        children=[
            cbstr(SuitInt),
            SuitBstr,
        ]
    )


class SuitHeaderMap(SuitKeyValue):
    """Representation of SUIT header map."""

    _metadata = Metadata(
        map={
            suit_cose_algorithm_id: SuitcoseAlg,
            suit_cose_key_id: SuitcoseKeyId,
            suit_cose_iv: SuitHex,
        }
    )


class SuitHeaderMapOptional(SuitUnion):
    """Representation of COSE_Encrypt_ciphertext item."""

    _metadata = Metadata(
        children=[
            SuitHeaderMap,
            SuitEmptyBstr,
        ]
    )

    @classmethod
    def from_obj(cls, obj) -> SuitUnion:
        """Restore SUIT representation from passed object."""
        value = None
        if isinstance(obj, dict):
            value = SuitEmptyBstr.from_obj("") if obj == {} else SuitHeaderMap.from_obj(obj)
        elif obj == "" or obj == b"":
            value = SuitEmptyBstr.from_obj("")
        else:
            raise ValueError(f"Expected dict empty string or empty sequence of bytes received: {obj}")

        return cls(value)


class SuitHeaderData(SuitUnion):
    """Abstract element to define possible sub-elements."""

    _metadata = Metadata(
        children=[
            SuitHeaderMap,
        ]
    )


class SuitCwtPayload(SuitKeyValue):
    """Representation of CBOR Web Token."""

    _metadata = Metadata(
        map={
            # Fields defined in RFC 8392
            suit_issuer: SuitTstr,
            suit_subject: SuitTstr,
            suit_audience: SuitTstr,
            suit_expiration_time: SuitInt,
            suit_not_before: SuitInt,
            suit_issued_at: SuitInt,
            suit_cw_id: SuitBstr,
        }
    )


class CoseSigStructure(SuitTupleNamed):
    """Representation of COSE Sig_structure."""

    _metadata = Metadata(
        map={
            "context": SuitTstr,
            "body_protected": cbstr(SuitHeaderMap),
            "external_add": SuitHex,
            "payload": cbstr(SuitDigestRaw),
        }
    )


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
            "protected": cbstr(SuitHeaderMap),
            "unprotected": SuitHeaderData,
            "payload": CoseSign1Payload,
            "signature": SuitHex,
        }
    )


class CoseSign1Tagged(SuitTag):
    """Representation of COSE_Sign1_Tagged item."""

    _metadata = Metadata(children=[CoseSign1], tag=Tag(18, "CoseSign1Tagged"))


class SuitAuthenticationBlock(SuitUnion):
    """Representation of SuitAuthentication_Block item."""

    _metadata = Metadata(children=[cbstr(CoseSign1Tagged)])


class SuitAuthentication(SuitTupleNamed):
    """Abstract element to define possible sub-elements."""

    _metadata = Metadata(map={"SuitDigest": cbstr(SuitDigest), "SuitAuthentication*": SuitAuthenticationBlock})


class SuitDelegation(SuitList):
    """Representation of SUIT delegation entry."""

    _metadata = Metadata(children=[SuitAuthenticationBlock])


class SuitDelegationChain(SuitList):
    """Representation of SUIT delegation chain."""

    _metadata = Metadata(children=[SuitDelegation])


# Encryption


class SuitCiphertextBytes(SuitHex):
    """Representation of SUIT ciphertext bytes."""

    pass


class CoseEncryptCiphertext(SuitUnion):
    """Representation of COSE_Encrypt_ciphertext item."""

    _metadata = Metadata(
        children=[
            SuitNull,
            SuitCiphertextBytes,
        ]
    )


class CoseRecipient(SuitTupleNamed):
    """Representation of COSE_Recipient item."""

    _metadata = Metadata(
        map={
            "protected": cbstr(SuitHeaderMapOptional),
            "unprotected": SuitHeaderData,
            "ciphertext": CoseEncryptCiphertext,
            "recipients*": SuitList,
        }
    )


class CoseRecipientList(SuitList):
    """Representation of a list of COSE_Recipient items."""

    _metadata = Metadata(children=[CoseRecipient])


# Fix cyclic dependencies between types
CoseRecipient._metadata.map["recipients*"] = CoseRecipientList


class CoseEncrypt(SuitTupleNamed):
    """Representation of COSE_Encrypt item."""

    _metadata = Metadata(
        map={
            "protected": cbstr(SuitHeaderMap),
            "unprotected": SuitHeaderData,
            "ciphertext": CoseEncryptCiphertext,
            "recipients": CoseRecipientList,
        }
    )


class CoseEncryptTagged(SuitTag):
    """Representation of COSE_Encrypt_Tagged item."""

    _metadata = Metadata(children=[CoseEncrypt], tag=Tag(96, "CoseEncryptTagged"))


class CoseEncStructure(SuitTupleNamed):
    """Representation of COSE Enc_structure."""

    _metadata = Metadata(
        map={
            "context": SuitTstr,
            "protected": cbstr(SuitHeaderMapOptional),
            "external_aad": SuitBstr,
        }
    )


class SuitEncryptionInfoExt(SuitBstr):
    """Representation of SUIT encryption info ext."""

    @classmethod
    def to_obj(self) -> dict:
        raise ValueError("Encryption info should be expanded to full structure by to_obj method")

    @classmethod
    def from_obj(cls, obj: dict) -> SuitBstr:
        """Restore SUIT representation from passed object."""
        if not isinstance(obj, dict):
            raise ValueError(f"Expected dict, received: {obj}")
        enc_info_bytes = b""
        if "raw" in obj.keys():
            enc_info_bytes = bytes.fromhex(obj["raw"])  # TODO: check this
        elif "file" in obj.keys():
            with open(obj["file"], "rb") as fd:
                enc_info_bytes = fd.read()
        else:
            raise ValueError(f"Unable to parse encryption info: {obj}")
        # the value in enc_info_bytes is already bstr wrapped - we have
        # to deserialize it, so that the SuitBstr to_cbor method returns the correct value
        return super().from_cbor(super().deserialize_cbor(enc_info_bytes))

    @classmethod
    def from_cbor(self) -> dict:
        raise ValueError(f"Encryption info should be created as serialized CoseEncryptTagged object from cbor")


class SuitEncryptionInfo(SuitUnion):
    """Representation of SUIT digest."""

    _metadata = Metadata(children=[cbstr(CoseEncryptTagged), SuitEncryptionInfoExt])
