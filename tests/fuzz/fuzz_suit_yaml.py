#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Fuzz suit-generator."""

import sys
import atheris
import yaml

with atheris.instrument_imports():
    from suit_generator.suit.envelope import SuitEnvelopeTagged

input_yaml = """SUIT_Envelope_Tagged:
  suit-authentication-wrapper:
    SuitDigest:
      suit-digest-algorithm-id: cose-alg-sha-256
      suit-digest-bytes: abe742c95d30b5d0dcc33e03cc939e563b41673cd9c6d0c6d06a5300c9af182e
  suit-manifest:
    suit-manifest-version: 1
    suit-manifest-sequence-number: 1
    suit-common:
      suit-components:
      - - MEM
        - 0
        - 524288
        - 0
      suit-shared-sequence:
      - suit-directive-override-parameters:
          suit-parameter-vendor-identifier:
            raw: 7617daa571fd5a858f94e28d735ce9f4
          suit-parameter-class-identifier:
            raw: 5b469fd190ee539ca318681b03695e36
          suit-parameter-image-digest:
            suit-digest-algorithm-id: cose-alg-sha-256
            suit-digest-bytes: 9c4b47c223b27e796d430b2078322f4069ded55f3d4092180f20dec90a61c9ff
          suit-parameter-image-size:
            raw: 1024
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
        suit-parameter-uri: '#file.bin'
    - suit-directive-fetch:
      - suit-send-record-failure
    - suit-condition-image-match:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    suit-text:
      suit-digest-algorithm-id: cose-alg-sha-256
      suit-digest-bytes: 40c4a598cc3b9c6030bb008f7eb3bda61af4e7af09a83cad2eb5fae5b0517a89
    suit-manifest-component-id:
    - INSTLD_MFST
    - raw: {suit_manifest_component_id}
  suit-text:
    en:
      '["MEM", 0, 524288, 0]':
        suit-text-vendor-name: Nordic Semiconductor ASA
        suit-text-model-name: test
        suit-text-vendor-domain: nordicsemi.com
        suit-text-model-info: The test application
        suit-text-component-description: Sample application for test
        suit-text-component-version: v1.0.0
  suit-integrated-payloads:
    '#file.bin': file.bin
"""


def fuzz_yaml_component_id(data):
    """Fuzz yaml input."""
    try:
        fdp = atheris.FuzzedDataProvider(data)
        fuzz_bytes = fdp.ConsumeBytes(16).hex()
        fuzz_data = input_yaml.format(
            suit_manifest_component_id=fuzz_bytes,
        )
        fuzz_object = yaml.load(fuzz_data)
        env = SuitEnvelopeTagged.from_obj(fuzz_object)
        cbor1 = env.to_cbor()
        env2 = SuitEnvelopeTagged.from_cbor(cbor1)
        env2.to_cbor()
    except ValueError:
        # ValueError is expected for some payloads since it's used by all suit-generator levels to report
        # not valid data.
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, fuzz_yaml_component_id)
    atheris.Fuzz()
