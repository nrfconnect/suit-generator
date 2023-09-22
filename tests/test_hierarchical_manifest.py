#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for envelope.py implementation."""
import json
import os
import pathlib
import deepdiff
import pytest
from cryptography.hazmat.primitives import hashes
from suit_generator.envelope import SuitEnvelope
from suit_generator.input_output import FileTypeException

TEMP_DIRECTORY = pathlib.Path("test_test_data")

TEST_YAML_STRING_UNSIGNED_ALIASES = """SUIT_Dependent_Manifests:
    - app_envelope: &app
        SUIT_Envelope_Tagged:
          suit-authentication-wrapper:
            SuitDigest:
              suit-digest-algorithm-id: cose-alg-sha-256
          suit-manifest:
            suit-manifest-version: 1
            suit-manifest-sequence-number: 1
            suit-common:
              suit-components:
              - - M
                - 0x02
                - 0x0E0AA000
                - 0x0007f800
              suit-shared-sequence:
              - suit-directive-override-parameters:
                  suit-parameter-vendor-identifier:
                    RFC4122_UUID: nordicsemi.com
                  suit-parameter-class-identifier:
                    RFC4122_UUID:
                      namespace: nordicsemi.com
                      name: nRF54H20_sample_app
                  suit-parameter-image-digest:
                    suit-digest-algorithm-id: cose-alg-sha-256
                    suit-digest-bytes:
                      file: app.bin
                  suit-parameter-image-size:
                    file: app.bin
              - suit-condition-vendor-identifier:
                - suit-send-record-success
                - suit-send-record-failure
                - suit-send-sysinfo-success
                - suit-send-sysinfo-failure
              - suit-condition-class-identifier:
                - suit-send-record-success
                - suit-send-record-failure
                - suit-send-sysinfo-success
                - suit-send-sysinfo-failure
            suit-validate:
            - suit-condition-image-match:
              - suit-send-record-success
              - suit-send-record-failure
              - suit-send-sysinfo-success
              - suit-send-sysinfo-failure
            suit-invoke:
            - suit-directive-invoke:
              - suit-send-record-failure
            suit-install:
            - suit-directive-override-parameters:
                suit-parameter-uri: '#app.bin'
            - suit-directive-fetch:
              - suit-send-record-failure
            - suit-condition-image-match:
              - suit-send-record-success
              - suit-send-record-failure
              - suit-send-sysinfo-success
              - suit-send-sysinfo-failure
            suit-text:
              suit-digest-algorithm-id: cose-alg-sha-256
            suit-manifest-component-id:
            - I
            - RFC4122_UUID:
                namespace: nordicsemi.com
                name: nRF54H20_sample_app
          suit-text:
            '["M", 2, 235577344, 522240]':
              suit-text-vendor-name: Nordic Semiconductor ASA
              suit-text-model-name: nRF54H20_cpuapp
              suit-text-vendor-domain: nordicsemi.com
              suit-text-model-info: The nRF54H20 application core
              suit-text-component-description: Sample application core FW
              suit-text-component-version: v1.0.0
          suit-integrated-payloads:
            '#app.bin': app.bin
    - radio_envelope: &rad
        SUIT_Envelope_Tagged:
          suit-authentication-wrapper:
            SuitDigest:
              suit-digest-algorithm-id: cose-alg-sha-256
          suit-manifest:
            suit-manifest-version: 1
            suit-manifest-sequence-number: 1
            suit-common:
              suit-components:
              - - M
                - 0x03
                - 0x0E054000
                - 0x00055800
              suit-shared-sequence:
              - suit-directive-override-parameters:
                  suit-parameter-vendor-identifier:
                    RFC4122_UUID: nordicsemi.com
                  suit-parameter-class-identifier:
                    RFC4122_UUID:
                      namespace: nordicsemi.com
                      name: nRF54H20_sample_rad
                  suit-parameter-image-digest:
                    suit-digest-algorithm-id: cose-alg-sha-256
                    suit-digest-bytes:
                      file: rad.bin
                  suit-parameter-image-size:
                    file: rad.bin
              - suit-condition-vendor-identifier:
                - suit-send-record-success
                - suit-send-record-failure
                - suit-send-sysinfo-success
                - suit-send-sysinfo-failure
              - suit-condition-class-identifier:
                - suit-send-record-success
                - suit-send-record-failure
                - suit-send-sysinfo-success
                - suit-send-sysinfo-failure
            suit-validate:
            - suit-condition-image-match:
              - suit-send-record-success
              - suit-send-record-failure
              - suit-send-sysinfo-success
              - suit-send-sysinfo-failure
            suit-invoke:
            - suit-directive-invoke:
              - suit-send-record-failure
            suit-install:
            - suit-directive-override-parameters:
                suit-parameter-uri: '#rad.bin'
            - suit-directive-fetch:
              - suit-send-record-failure
            - suit-condition-image-match:
              - suit-send-record-success
              - suit-send-record-failure
              - suit-send-sysinfo-success
              - suit-send-sysinfo-failure
            suit-text:
              suit-digest-algorithm-id: cose-alg-sha-256
            suit-manifest-component-id:
            - I
            - RFC4122_UUID:
                namespace: nordicsemi.com
                name: nRF54H20_sample_rad
          suit-text:
            '["M", 3, 235225088, 350208]':
              suit-text-vendor-name: Nordic Semiconductor ASA
              suit-text-model-name: nRF54H20_cpurad
              suit-text-vendor-domain: nordicsemi.com
              suit-text-model-info: The nRF54H20 radio core
              suit-text-component-description: Sample radio core FW
              suit-text-component-version: v1.0.0
          suit-integrated-payloads:
            '#rad.bin': rad.bin
SUIT_Envelope_Tagged:
  suit-authentication-wrapper:
    SuitDigest:
      suit-digest-algorithm-id: cose-alg-sha-256
  suit-manifest:
    suit-manifest-version: 1
    suit-manifest-sequence-number: 1
    suit-common:
      suit-components:
      - - C
        - 0
      - - I
        - RFC4122_UUID:
            namespace: nordicsemi.com
            name: nRF54H20_sample_rad
      - - I
        - RFC4122_UUID:
            namespace: nordicsemi.com
            name: nRF54H20_sample_app
      suit-shared-sequence:
      - suit-directive-set-component-index: 1
      - suit-directive-override-parameters:
          suit-parameter-vendor-identifier:
            RFC4122_UUID: nordicsemi.com
          suit-parameter-class-identifier:
            RFC4122_UUID:
              namespace: nordicsemi.com
              name: nRF54H20_sample_rad

      - suit-directive-set-component-index: 2
      - suit-directive-override-parameters:
          suit-parameter-vendor-identifier:
            RFC4122_UUID: nordicsemi.com
          suit-parameter-class-identifier:
            RFC4122_UUID:
              namespace: nordicsemi.com
              name: nRF54H20_sample_app

      - suit-directive-set-component-index: [1, 2]
      - suit-condition-vendor-identifier:
        - suit-send-record-success
        - suit-send-record-failure
        - suit-send-sysinfo-success
        - suit-send-sysinfo-failure
      - suit-condition-class-identifier:
        - suit-send-record-success
        - suit-send-record-failure
        - suit-send-sysinfo-success
        - suit-send-sysinfo-failure
      suit-dependencies:
        # Key is the index of suit-components that describe the dependency manifest
        "0": {}
        "1": {}
        "2": {}

    suit-validate:
    - suit-directive-set-component-index: [1, 2]
    - suit-condition-dependency-integrity:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    - suit-directive-process-dependency:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure

    suit-invoke:
    - suit-directive-set-component-index: [1, 2]
    - suit-condition-dependency-integrity:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    - suit-directive-process-dependency:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure

    suit-install:
    - suit-directive-set-component-index: 0
    - suit-directive-override-parameters:
        suit-parameter-uri: '#rad.suit'
        suit-parameter-image-digest:
          suit-digest-algorithm-id: cose-alg-sha-256
          suit-digest-bytes:
            envelope: *rad
        suit-parameter-image-size:
          envelope: *rad
    - suit-directive-fetch:
      - suit-send-record-failure
    - suit-condition-image-match:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    - suit-condition-dependency-integrity:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    - suit-directive-process-dependency:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    # Manifest copied to I/RAD s a result of sequence completion

    - suit-directive-override-parameters:
        suit-parameter-uri: '#app.suit'
        suit-parameter-image-digest:
          suit-digest-algorithm-id: cose-alg-sha-256
          suit-digest-bytes:
            envelope: *app
        suit-parameter-image-size:
          envelope: *app
    - suit-directive-fetch:
      - suit-send-record-failure
    - suit-condition-image-match:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    - suit-condition-dependency-integrity:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    - suit-directive-process-dependency:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    # Manifest copied to I/APP s a result of sequence completion

    # Manifest copied to I/ROOT s a result of sequence completion
    suit-text:
      suit-digest-algorithm-id: cose-alg-sha-256
    suit-manifest-component-id:
    - I
    - RFC4122_UUID:
        namespace: nordicsemi.com
        name: nRF54H20_sample_root
  suit-text:
    '["C", 0]':
      suit-text-vendor-name: Nordic Semiconductor ASA
      suit-text-model-name: nRF54H20
      suit-text-vendor-domain: nordicsemi.com
      suit-text-model-info: The nRF54H20 root manifest
      suit-text-component-description: Sample root manifest
      suit-text-component-version: v1.0.0
  suit-integrated-dependencies:
    '#rad.suit': *rad
    '#app.suit': *app

"""


@pytest.fixture
def setup_and_teardown(tmp_path_factory):
    """Create and cleanup environment."""
    # Setup environment
    #   - create temp directory
    #   - create input json files
    #   - create binary file
    start_directory = os.getcwd()
    path = tmp_path_factory.mktemp(TEMP_DIRECTORY)
    print(f"temp {path}")
    os.chdir(path)
    with open("envelope_1.yaml", "w") as fh:
        fh.write(TEST_YAML_STRING_UNSIGNED_ALIASES)
    with open("rad.bin", "wb") as fh:
        fh.write(b"\xde\xad\xbe\xef")
    with open("app.bin", "wb") as fh:
        fh.write(b"\xc0\xff\xee\x00")
    yield
    # Cleanup environment
    #   - remove temp directory
    os.chdir(start_directory)


@pytest.mark.parametrize("input_data", ["envelope_1"])
def test_envelope_creation(setup_and_teardown, input_data):
    envelope = SuitEnvelope()
    envelope.load(f"{input_data}.yaml", input_type="yaml")
    envelope.dump(f"{input_data}.suit", output_type="suit")


def calculate_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def test_envelope_unsigned_creation_and_parsing(setup_and_teardown):
    envelope = SuitEnvelope()
    # create envelope_1
    envelope.load("envelope_1.yaml", input_type="yaml")
    envelope.dump("envelope_1.suit", output_type="suit")
    # parse envelope_1
    envelope.load("envelope_1.suit", input_type="suit")
    envelope.dump("envelope_1_copy.yaml", output_type="yaml")
    # create envelope_1_copy based on new input json file
    envelope.load("envelope_1_copy.yaml", input_type="yaml")
    envelope.dump("envelope_1_copy.suit", output_type="suit")
    # compare create yaml and suit files
    with open("envelope_1.yaml") as fh_1, open("envelope_1_copy.yaml") as fh_2:
        import yaml
        d1 = yaml.load(fh_1.read(), Loader=yaml.SafeLoader)
        d2 = yaml.load(fh_2.read(), Loader=yaml.SafeLoader)
        diff = deepdiff.DeepDiff(
            d1,
            d2,
            exclude_paths=[
                "root['SUIT_Dependent_Manifests']",  # TODO: shall be somehow restored
                "root['SUIT_Envelope_Tagged']['suit-integrated-payloads']",
                "root['SUIT_Envelope_Tagged']['suit-integrated-dependencies']"
            ],
            exclude_regex_paths=[
                r"root(\[.*\])*\['raw'\]",
                r"root(\[.*\])*\['suit-digest-bytes'\]",
                r"root(\[.*\])*\['RFC4122_UUID'\]",
                r"root(\[.*\])*\['envelope'\]"  # TODO: shall be somehow restored
            ]
        )
        assert diff == {}
    with open("envelope_1.suit", "rb") as fh_suit_1, open("envelope_1_copy.suit", "rb") as fh_suit_2:
        assert calculate_hash(fh_suit_1.read()) == calculate_hash(fh_suit_2.read())
