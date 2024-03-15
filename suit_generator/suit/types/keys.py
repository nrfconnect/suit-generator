#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""SUIT keys names and ids definition."""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class suit_key:
    """General SUIT parameter metadata."""

    id: None | int = None
    name: None | str = None


class suit_digest_bytes(suit_key):
    """suit-digest-bytes metadata."""

    name = "suit-digest-bytes"


class suit_digest_algorithm_id(suit_key):
    """suit-digest-algorithm-id metadata."""

    name = "suit-digest-algorithm-id"


class suit_manifest_version(suit_key):
    """suit-manifest-version metadata."""

    id = 1
    name = "suit-manifest-version"


class suit_manifest_sequence_number(suit_key):
    """suit-manifest-sequence-number metadata."""

    id = 2
    name = "suit-manifest-sequence-number"


class suit_directive_process_dependency(suit_key):
    """suit-directive-process-dependency metadata."""

    id = 11
    name = "suit-directive-process-dependency"


class suit_directive_set_component_index(suit_key):
    """suit-directive-set-component-index metadata."""

    id = 12
    name = "suit-directive-set-component-index"


class suit_directive_try_each(suit_key):
    """suit-directive-try-each metadata."""

    id = 15
    name = "suit-directive-try-each"


class suit_directive_write(suit_key):
    """suit-diretive-write metadata."""

    id = 18
    name = "suit-directive-write"


class suit_directive_set_parameters(suit_key):
    """suit-directive-set-parameters metadata."""

    id = 19
    name = "suit-directive-set-parameters"


class suit_directive_override_parameters(suit_key):
    """suit-directive-override-parameters metadata."""

    id = 20
    name = "suit-directive-override-parameters"


class suit_directive_fetch(suit_key):
    """suit-directive-fetch metadata."""

    id = 21
    name = "suit-directive-fetch"


class suit_directive_copy(suit_key):
    """suit-directive-copy metadata."""

    id = 22
    name = "suit-directive-copy"


class suit_directive_invoke(suit_key):
    """suit-directive-invoke metadata."""

    id = 23
    name = "suit-directive-invoke"


class suit_directive_swap(suit_key):
    """suit-directive-swap metadata."""

    id = 31
    name = "suit-directive-swap"


class suit_directive_run_sequence(suit_key):
    """suit-directive-run-sequence metadata."""

    id = 32
    name = "suit-directive-run-sequence"


class suit_directive_unlink(suit_key):
    """suit-directive-unlink metadata."""

    id = 33
    name = "suit-directive-unlink"


class suit_parameter_version(suit_key):
    """suit-parameter-version metadata."""

    id = 28
    name = "suit-parameter-version"


class suit_parameter_version_comparison_type(suit_key):
    """suit-parameter-version-comparison-type metadata."""

    id = 1
    name = "suit-parameter-version-comparison-type"


class suit_parameter_version_comparison_value(suit_key):
    """suit-parameter-version-comparison-value metadata."""

    id = 2
    name = "suit-parameter-version-comparison-value"


class suit_parameter_vendor_identifier(suit_key):
    """suit-parameter-vendor-identifier metadata."""

    id = 1
    name = "suit-parameter-vendor-identifier"


class suit_parameter_class_identifier(suit_key):
    """suit-parameter-class-identifier metadata."""

    id = 2
    name = "suit-parameter-class-identifier"


class suit_parameter_image_digest(suit_key):
    """suit-parameter-image-digest metadata."""

    id = 3
    name = "suit-parameter-image-digest"


class suit_parameter_component_slot(suit_key):
    """suit-parameter-component-slot metadata."""

    id = 5
    name = "suit-parameter-component-slot"


class suit_parameter_strict_order(suit_key):
    """suit-parameter-strict-order metadata."""

    id = 12
    name = "suit-parameter-strict-order"


class suit_parameter_soft_failure(suit_key):
    """suit-parameter-soft-failure metadata."""

    id = 13
    name = "suit-parameter-soft-failure"


class suit_parameter_image_size(suit_key):
    """suit-parameter-image-size metadata."""

    id = 14
    name = "suit-parameter-image-size"


class suit_parameter_content(suit_key):
    """suit-parameter-content metadata."""

    id = 18
    name = "suit-parameter-content"


class suit_parameter_uri(suit_key):
    """suit-parameter-uri metadata."""

    id = 21
    name = "suit-parameter-uri"


class suit_parameter_source_component(suit_key):
    """suit-parameter-source-component metadata."""

    id = 22
    name = "suit-parameter-source-component"


class suit_parameter_invoke_args(suit_key):
    """suit-parameter-invoke-args metadata."""

    id = 23
    name = "suit-parameter-invoke-args"


class suit_parameter_device_identifier(suit_key):
    """suit-parameter-device-identifier metadata."""

    id = 24
    name = "suit-parameter-device-identifier"


class suit_dependencies(suit_key):
    """suit-dependencies metadata."""

    id = 1
    name = "suit-dependencies"


class suit_components(suit_key):
    """suit-components metadata."""

    id = 2
    name = "suit-components"


class suit_shared_sequence(suit_key):
    """suit_shared_sequence metadata."""

    id = 4
    name = "suit-shared-sequence"


class suit_common(suit_key):
    """suit-common metadata."""

    id = 3
    name = "suit-common"


class suit_reference_uri:
    """suit-reference-uri metadata."""

    id = 4
    name = "suit-reference-uri"


class suit_manifest_component_id(suit_key):
    """suit-manifest-component-id metadata."""

    id = 5
    name = "suit-manifest-component-id"


class suit_current_version(suit_key):
    """suit-current-version metadata."""

    id = 6
    name = "suit-current-version"


class suit_validate(suit_key):
    """suit-validate metadata."""

    id = 7
    name = "suit-validate"


class suit_load(suit_key):
    """suit-load metadata."""

    id = 8
    name = "suit-load"


class suit_invoke(suit_key):
    """suit-invoke metadata."""

    id = 9
    name = "suit-invoke"


class suit_payload_fetch(suit_key):
    """suit-payload-fetch metadata."""

    id = 16
    name = "suit-payload-fetch"


class suit_install(suit_key):
    """suit-install metadata."""

    id = 17
    name = "suit-install"


class suit_text(suit_key):
    """suit-install metadata."""

    id = 23
    name = "suit-text"


class suit_integrated_payloads(suit_key):
    """suit-integrated-payloads metadata."""

    id = -1
    name = "suit-integrated-payloads"


class suit_integrated_dependencies(suit_key):
    """suit-integrated-dependencies metadata."""

    id = -2
    name = "suit-integrated-dependencies"


class suit_uninstall(suit_key):
    """suit-uninstall metadata."""

    id = 24
    name = "suit_uninstall"


class suit_text_manifest_description(suit_key):
    """suit-text-manifest-description metadata."""

    id = 1
    name = "suit-text-manifest-description"


class suit_text_update_description(suit_key):
    """suit-text-update-description metadata."""

    id = 2
    name = "suit-text-update-description"


class suit_text_manifest_json_source(suit_key):
    """suit-text-manifest-json-source metadata."""

    id = 3
    name = "suit-text-manifest-json-source"


class suit_text_manifest_yaml_source(suit_key):
    """suit-text-manifest-yaml-source metadata."""

    id = 4
    name = "suit-text-manifest-yaml-source"


class suit_text_vendor_name(suit_key):
    """suit-text-vendor-name metadata."""

    id = 1
    name = "suit-text-vendor-name"


class suit_text_model_name(suit_key):
    """suit-text-model-name metadata."""

    id = 2
    name = "suit-text-model-name"


class suit_text_vendor_domain(suit_key):
    """suit-text-vendor-domain metadata."""

    id = 3
    name = "suit-text-vendor-domain"


class suit_text_model_info(suit_key):
    """suit-text-model-info metadata."""

    id = 4
    name = "suit-text-model-info"


class suit_text_component_description(suit_key):
    """suit-text-component-description metadata."""

    id = 5
    name = "suit-text-component-description"


class suit_text_component_version(suit_key):
    """suit-text-component-version metadata."""

    id = 6
    name = "suit-text-component-version"


class suit_delegation(suit_key):
    """suit-delegation metadata."""

    id = 1
    name = "suit-delegation"


class suit_authentication_wrapper(suit_key):
    """suit-authentication-wrapper metadata."""

    id = 2
    name = "suit-authentication-wrapper"


class suit_manifest(suit_key):
    """suit-manifest metadata."""

    id = 3
    name = "suit-manifest"


class suit_dependency_resolution(suit_key):
    """suit-dependency-resolution metadata."""

    id = 15
    name = "suit-dependency-resolution"


class suit_candidate_verification(suit_key):
    """suit-candidate-verification metadata."""

    id = 18
    name = "suit-candidate-verification"


class suit_condition_version(suit_key):
    """suit-condition-version metadata."""

    id = 28
    name = "suit-condition-version"


class suit_condition_version_comparison_greater(suit_key):
    """suit-condition-version-comparison-greater metadata."""

    id = 1
    name = "suit-condition-version-comparison-greater"


class suit_condition_version_comparison_greater_equal(suit_key):
    """suit-condition-version-comparison-greater-equal metadata."""

    id = 2
    name = "suit-condition-version-comparison-greater-equal"


class suit_condition_version_comparison_equal(suit_key):
    """suit-condition-version-comparison-equal metadata."""

    id = 3
    name = "suit-condition-version-comparison-equal"


class suit_condition_version_comparison_lesser_equal(suit_key):
    """suit-condition-version-comparison-lesser-equal metadata."""

    id = 4
    name = "suit-condition-version-comparison-lesser-equal"


class suit_condition_version_comparison_lesser(suit_key):
    """suit-condition-version-comparison-lesser metadata."""

    id = 5
    name = "suit-condition-version-comparison-lesser"


class suit_condition_vendor_identifier(suit_key):
    """suit-condition-vendor-identifier metadata."""

    id = 1
    name = "suit-condition-vendor-identifier"


class suit_condition_class_identifier(suit_key):
    """suit-condition-class-identifier metadata."""

    id = 2
    name = "suit-condition-class-identifier"


class suit_condition_image_match(suit_key):
    """suit-condition-image-match metadata."""

    id = 3
    name = "suit-condition-image-match"


class suit_condition_component_slot(suit_key):
    """suit-condition-component-slot metadata."""

    id = 5
    name = "suit-condition-component-slot"


class suit_condition_check_content(suit_key):
    """suit-condition-check-content metadata."""

    id = 6
    name = "suit-condition-check-content"


class suit_condition_dependency_integrity(suit_key):
    """suit-condition-dependency-integrity metadata."""

    id = 7
    name = "suit-condition-dependency-integrity"


class suit_condition_is_dependency(suit_key):
    """suit-condition-is-dependency metadata."""

    id = 8
    name = "suit-condition-is-dependency"


class suit_condition_abort(suit_key):
    """suit-condition-abort metadata."""

    id = 14
    name = "suit-condition-abort"


class suit_condition_device_identifier(suit_key):
    """suit-condition-device-identifier metadata."""

    id = 24
    name = "suit-condition-device-identifier"


class suit_dependency_prefix(suit_key):
    """suit-dependency-prefix metadata."""

    id = 1
    name = "suit-dependency-prefix"


class suit_cose_algorithm_id(suit_key):
    """suit-cose-algorithm-id metadata."""

    id = 1
    name = "suit-cose-algorithm-id"


class suit_cose_key_id(suit_key):
    """suit-cose-key-id metadata."""

    id = 4
    name = "suit-cose-key-id"


class suit_issuer(suit_key):
    """CWT Issuer metadata."""

    id = 1
    name = "Issuer"


class suit_subject(suit_key):
    """CWT Subject metadata."""

    id = 2
    name = "Subject"


class suit_audience(suit_key):
    """CWT Audience metadata."""

    id = 3
    name = "Audience"


class suit_expiration_time(suit_key):
    """CWT Expiration Time metadata."""

    id = 4
    name = "Expiration Time"


class suit_not_before(suit_key):
    """CWT Not Before metadata."""

    id = 5
    name = "Not Before"


class suit_issued_at(suit_key):
    """CWT Issued At metadata."""

    id = 6
    name = "Issued At"


class suit_cw_id(suit_key):
    """CWT CW ID metadata."""

    id = 7
    name = "CW ID"


class cose_alg_sha_256(suit_key):
    """Cose algorithm metadata."""

    id = -16
    name = "cose-alg-sha-256"


class cose_alg_shake128(suit_key):
    """Cose algorithm metadata."""

    id = -18
    name = "cose-alg-shake128"


class cose_alg_sha_384(suit_key):
    """Cose algorithm metadata."""

    id = -43
    name = "cose-alg-sha-384"


class cose_alg_sha_512(suit_key):
    """Cose algorithm metadata."""

    id = -44
    name = "cose-alg-sha-512"


class cose_alg_shake256(suit_key):
    """Cose algorithm metadata."""

    id = -45
    name = "cose-alg-shake256"


class cose_alg_es_256(suit_key):
    """Cose algorithm metadata."""

    id = -7
    name = "cose-alg-es-256"


class cose_alg_es_384(suit_key):
    """Cose algorithm metadata."""

    id = -35
    name = "cose-alg-es-384"


class cose_alg_es_521(suit_key):
    """Cose algorithm metadata."""

    id = -36
    name = "cose-alg-es-521"


class cose_alg_eddsa(suit_key):
    """Cose algorithm metadata."""

    id = -8
    name = "cose-alg-eddsa"


class suit_send_record_success(suit_key):
    """Reporting policy bit."""

    id = 1
    name = "suit-send-record-success"


class suit_send_record_failure(suit_key):
    """Reporting policy bit."""

    id = 2
    name = "suit-send-record-failure"


class suit_send_sysinfo_success(suit_key):
    """Reporting policy bit."""

    id = 4
    name = "suit-send-sysinfo-success"


class suit_send_sysinfo_failure(suit_key):
    """Reporting policy bit."""

    id = 8
    name = "suit-send-sysinfo-failure"
