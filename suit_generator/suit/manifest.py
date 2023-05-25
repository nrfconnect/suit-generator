#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""SUIT manifest elements representation.

Code inspired by/based on https://github.com/tomchy/suit-composer.
"""
import uuid
from os.path import getsize

from suit_generator.suit.types.common import (
    SuitUint,
    SuitKeyValue,
    SuitKeyValueUnnamed,
    SuitKeyValueTuple,
    Metadata,
    SuitUnion,
    SuitList,
    SuitTstr,
    SuitBstr,
    SuitBool,
    SuitListUint,
    SuitBitfield,
    SuitEnum,
    cbstr,
    bchar,
)
from suit_generator.suit.authentication import SuitDigest
from suit_generator.suit.types.keys import (
    suit_parameter_vendor_identifier,
    suit_parameter_class_identifier,
    suit_parameter_image_digest,
    suit_parameter_component_slot,
    suit_parameter_strict_order,
    suit_parameter_soft_failure,
    suit_parameter_image_size,
    suit_parameter_content,
    suit_parameter_uri,
    suit_parameter_source_component,
    suit_parameter_invoke_args,
    suit_parameter_device_identifier,
    suit_directive_set_component_index,
    suit_directive_try_each,
    suit_directive_write,
    suit_directive_set_parameters,
    suit_directive_override_parameters,
    suit_directive_fetch,
    suit_directive_copy,
    suit_directive_invoke,
    suit_directive_swap,
    suit_directive_run_sequence,
    suit_directive_unlink,
    suit_dependencies,
    suit_components,
    suit_shared_sequence,
    suit_manifest_version,
    suit_manifest_sequence_number,
    suit_common,
    suit_condition_vendor_identifier,
    suit_condition_class_identifier,
    suit_condition_image_match,
    suit_condition_component_slot,
    suit_condition_check_content,
    suit_condition_is_dependency,
    suit_condition_abort,
    suit_condition_device_identifier,
    suit_dependency_prefix,
    suit_send_record_success,
    suit_send_record_failure,
    suit_send_sysinfo_success,
    suit_send_sysinfo_failure,
    suit_reference_uri,
    suit_validate,
    suit_load,
    suit_invoke,
    suit_payload_fetch,
    suit_install,
    suit_text_manifest_description,
    suit_text_manifest_json_source,
    suit_text_manifest_yaml_source,
    suit_text_update_description,
    suit_text_vendor_name,
    suit_text_model_name,
    suit_text_vendor_domain,
    suit_text_model_info,
    suit_text_component_description,
    suit_text_component_version,
    suit_uninstall,
    suit_text,
)


class SuitIndex(SuitUnion):
    """Representation of SUIT index value."""

    _metadata = Metadata(
        children=[
            SuitUint,
            SuitBool,
            SuitListUint,
        ]
    )


class SuitRepPolicyBits(SuitEnum):
    """Representation of SUIT reporting policy bits."""

    _metadata = Metadata(
        children=[
            suit_send_record_success,
            suit_send_record_failure,
            suit_send_sysinfo_success,
            suit_send_sysinfo_failure,
        ]
    )


class SuitRepPolicy(SuitBitfield):
    """Representation of SUIT reporting policy."""

    _bit_class = SuitRepPolicyBits
    _bit_length = 8


class SuitUUID(SuitBstr):
    """Representation of SUIT UUID identifier."""

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        if not isinstance(obj, dict):
            raise ValueError(f"Expected dict, received: {obj}")
        if "RFC4122_UUID" in obj.keys():
            entry = uuid.uuid5(uuid.NAMESPACE_DNS, obj["RFC4122_UUID"]).bytes
            return cls(entry)
        elif "raw" in obj.keys():
            return super().from_obj(obj["raw"])
        else:
            raise ValueError(f"Unable to parse UUID: {obj}")

    def to_obj(self):
        """Dump SUIT representation to object."""
        return {"raw": super().to_obj()}


class SuitImageSize(SuitUint):
    """Representation of SUIT image size parameter."""

    def to_obj(self):
        """Dump SUIT representation to object."""
        return {"raw": super().to_obj()}

    @classmethod
    def from_obj(cls, obj):
        """Restore SUIT representation from passed object."""
        if not isinstance(obj, dict):
            raise ValueError(f"Expected dict, received: {obj}")
        if "raw" in obj.keys():
            return super().from_obj(obj["raw"])
        elif "file" in obj.keys():
            return super().from_obj(getsize(obj["file"]))
        else:
            raise ValueError(f"Unable to parse image size: {obj}")


class SuitParameters(SuitKeyValue):
    """Representation of SUIT parameters."""

    _metadata = Metadata(
        map={
            suit_parameter_vendor_identifier: SuitUUID,
            suit_parameter_class_identifier: SuitUUID,
            suit_parameter_image_digest: cbstr(SuitDigest),
            suit_parameter_component_slot: SuitUint,
            suit_parameter_strict_order: SuitBool,
            suit_parameter_soft_failure: SuitBool,
            suit_parameter_image_size: SuitImageSize,
            suit_parameter_content: SuitBstr,
            suit_parameter_uri: SuitTstr,
            suit_parameter_source_component: SuitUint,
            suit_parameter_invoke_args: SuitBstr,
            suit_parameter_device_identifier: SuitUUID,
        }
    )


class SuitDirective(SuitKeyValueTuple):
    """Representation of SUIT directive."""

    _metadata = Metadata(
        map={
            suit_directive_set_component_index: SuitIndex,
            suit_directive_try_each: SuitList,
            suit_directive_write: SuitRepPolicy,
            suit_directive_set_parameters: SuitParameters,
            suit_directive_override_parameters: SuitParameters,
            suit_directive_fetch: SuitRepPolicy,
            suit_directive_copy: SuitRepPolicy,
            suit_directive_invoke: SuitRepPolicy,
            suit_directive_swap: SuitRepPolicy,
            suit_directive_run_sequence: SuitBstr,
            suit_directive_unlink: SuitRepPolicy,
        }
    )


class SuitCondition(SuitKeyValueTuple):
    """Representation of SUIT condition."""

    _metadata = Metadata(
        map={
            suit_condition_vendor_identifier: SuitRepPolicy,
            suit_condition_class_identifier: SuitRepPolicy,
            suit_condition_image_match: SuitRepPolicy,
            suit_condition_component_slot: SuitRepPolicy,
            suit_condition_check_content: SuitRepPolicy,
            suit_condition_is_dependency: SuitRepPolicy,
            suit_condition_abort: SuitRepPolicy,
            suit_condition_device_identifier: SuitRepPolicy,
        }
    )


class SuitCommand(SuitUnion):
    """Representation of SUIT union.

    Suit union is an abstract element represents alternatives.
    """

    _metadata = Metadata(children=[SuitCondition, SuitDirective])


class SuitComponentIdentifierPart(SuitUnion):
    """Abstract element to define possible sub-elements."""

    _metadata = Metadata(children=[bchar(SuitTstr), cbstr(SuitUint), SuitBstr])


class SuitComponentIdentifier(SuitList):
    """Representation of SUIT component identifier."""

    _metadata = Metadata(children=[SuitComponentIdentifierPart])

    def to_obj(self):
        """Dump SUIT representation to object."""
        return [v.to_obj() for v in self.value]


class SuitTextComponentKeys(SuitKeyValue):
    """Representation of SUIT component keys."""

    _metadata = Metadata(
        map={
            suit_text_vendor_name: SuitTstr,
            suit_text_model_name: SuitTstr,
            suit_text_vendor_domain: SuitTstr,
            suit_text_model_info: SuitTstr,
            suit_text_component_description: SuitTstr,
            suit_text_component_version: SuitTstr,
        }
    )


class SuitTextKeys(SuitEnum):
    """Representation of SUIT keys."""

    _metadata = Metadata(
        children=[
            suit_text_manifest_description,
            suit_text_update_description,
            suit_text_manifest_json_source,
            suit_text_manifest_yaml_source,
        ]
    )


class SuitTextMap(SuitKeyValueUnnamed):
    """Representation of SUIT text map."""

    _metadata = Metadata(map={SuitComponentIdentifier: SuitTextComponentKeys, SuitTextKeys: SuitTstr})


class SuitSeverableText(SuitUnion):
    """Representation of SUIT severable text."""

    _metadata = Metadata(children=[SuitDigest, SuitTextMap])


class SuitDependencyMetadata(SuitKeyValue):
    """Representation of SUIT dependency metadata."""

    _metadata = Metadata(map={suit_dependency_prefix: SuitComponentIdentifier})


class SuitDependencies(SuitKeyValueUnnamed):
    """Representation of SUIT dependencies."""

    _metadata = Metadata(map={SuitUint: SuitDependencyMetadata})


class SuitComponents(SuitList):
    """Representation of SUIT components."""

    _metadata = Metadata(children=[SuitComponentIdentifier])


class SuitCommandSequence(SuitList):
    """Representation of SUIT command sequence."""

    _metadata = Metadata(children=[SuitCommand])
    _group = 2


class SuitSeverableCommandSequence(SuitUnion):
    """Representation of SUIT severable command sequence."""

    _metadata = Metadata(children=[cbstr(SuitCommandSequence), SuitDigest])


class SuitCommon(SuitKeyValue):
    """Representation of SUIT common."""

    _metadata = Metadata(
        map={
            suit_dependencies: SuitDependencies,
            suit_components: SuitComponents,
            suit_shared_sequence: cbstr(SuitCommandSequence),
        }
    )


class SuitManifest(SuitKeyValue):
    """Representation of SUIT manifest."""

    _metadata = Metadata(
        map={
            suit_manifest_version: SuitUint,
            suit_manifest_sequence_number: SuitUint,
            suit_common: cbstr(SuitCommon),
            suit_reference_uri: SuitTstr,
            suit_validate: cbstr(SuitCommandSequence),
            suit_load: cbstr(SuitCommandSequence),
            suit_invoke: cbstr(SuitCommandSequence),
            suit_payload_fetch: SuitSeverableCommandSequence,
            suit_install: SuitSeverableCommandSequence,
            suit_text: SuitSeverableText,
            suit_uninstall: cbstr(SuitCommandSequence),
        }
    )
