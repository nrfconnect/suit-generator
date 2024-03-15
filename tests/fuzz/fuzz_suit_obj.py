#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Fuzz suit-generator."""

import sys
import atheris
import json

with atheris.instrument_imports():
    from suit_generator.suit.envelope import SuitEnvelopeTagged

unsigned_envelope_json = """
{{
    "SUIT_Envelope_Tagged":
    {{
        "suit-authentication-wrapper":
        {{
            "SuitDigest":
            {{
                "suit-digest-algorithm-id": "{suit_digest_algorithm_id}",
                "suit-digest-bytes": "{suit_digest_bytes}"
            }}
        }},
        "suit-manifest":
        {{
            "suit-manifest-version": {suit_manifest_version},
            "suit-manifest-sequence-number": {suit_manifest_sequence_number},
            "suit-common":
            {{
                "suit-components":
                [
                    [
                        "M",
                        255,
                        235225088,
                        352256
                    ],
                    [
                        "M",
                        14,
                        772096000,
                        352256
                    ],
                    [
                        "D",
                        0
                    ]
                ],
                "suit-shared-sequence":
                [
                    {{
                        "suit-directive-set-component-index": 1
                    }},
                    {{
                        "suit-directive-override-parameters":
                        {{
                            "suit-parameter-vendor-identifier":
                            {{
                                "RFC4122_UUID": "nordicsemi.com"
                            }},
                            "suit-parameter-class-identifier":
                            {{
                                "raw": "d622bafd4337518590bc6368cda7fbca"
                            }}
                        }}
                    }},
                    {{
                        "suit-condition-vendor-identifier":
                        [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure"
                        ]
                    }},
                    {{
                        "suit-condition-class-identifier":
                        []
                    }},
                    {{
                        "suit-directive-set-component-index": true
                    }},
                    {{
                        "suit-directive-override-parameters":
                        {{
                            "suit-parameter-image-digest":
                            {{
                                "suit-digest-algorithm-id": "cose-alg-sha-256",
                                "suit-digest-bytes":
                                {{
                                    "file": "file.bin"
                                }}
                            }},
                            "suit-parameter-image-size":
                            {{
                                "file": "file.bin"
                            }}
                        }}
                    }}
                ],
                "suit-dependencies":
                {{
                    "0":
                    {{}},
                    "1":
                    {{
                        "suit-dependency-prefix":
                        [
                            "M",
                            1234
                        ]
                    }}
                }}
            }},
            "suit-install":
            [
                {{
                    "suit-directive-set-component-index": 2
                }},
                {{
                    "suit-directive-override-parameters":
                    {{
                        "suit-parameter-uri": "#file.bin"
                    }}
                }},
                {{
                    "suit-directive-fetch":
                    []
                }},
                {{
                    "suit-condition-image-match":
                    []
                }},
                {{
                    "suit-directive-set-component-index": 1
                }},
                {{
                    "suit-directive-override-parameters":
                    {{
                        "suit-parameter-source-component": 2
                    }}
                }},
                {{
                    "suit-directive-copy":
                    []
                }},
                {{
                    "suit-condition-image-match":
                    []
                }}
            ],
            "suit-validate":
            [
                {{
                    "suit-directive-set-component-index": 1
                }},
                {{
                    "suit-condition-image-match":
                    []
                }}
            ],
            "suit-load":
            [
                {{
                    "suit-directive-set-component-index": 0
                }},
                {{
                    "suit-directive-override-parameters":
                    {{
                        "suit-parameter-source-component": 1
                    }}
                }},
                {{
                    "suit-directive-run-sequence":
                    [
                        {{
                            "suit-directive-copy":
                            []
                        }},
                        {{
                            "suit-condition-image-match":
                            []
                        }}
                    ]
                }}
            ],
            "suit-invoke":
            [
                {{
                    "suit-directive-set-component-index": 0
                }},
                {{
                    "suit-directive-invoke":
                    []
                }}
            ],
            "suit-dependency-resolution":
            [
                {{
                    "suit-condition-is-dependency":
                    []
                }},
                {{
                    "suit-condition-dependency-integrity":
                    []
                }},
                {{
                    "suit-directive-process-dependency":
                    []
                }},
                {{
                    "suit-directive-try-each":
                    [
                        [
                            {{
                                "suit-condition-is-dependency":
                                []
                            }},
                            {{
                                "suit-condition-dependency-integrity":
                                []
                            }},
                            {{
                                "suit-directive-process-dependency":
                                []
                            }}
                        ],
                        []
                    ]
                }}
            ],
            "suit-manifest-component-id":
            [
                "I",
                {{
                    "RFC4122_UUID":
                    {{
                        "namespace": "nordicsemi.com",
                        "name": "nRF54H20_sample_root"
                    }}
                }}
            ]
        }},
        "suit-text":
        {{
            "en": {{
                "[\\"M\\", 2, 235577344, 352256]": {{
                    "suit-text-vendor-name": "{suit_text_vendor_name}",
                    "suit-text-model-name": "{suit_text_model_name}",
                    "suit-text-vendor-domain": "{suit_text_vendor_domain}",
                    "suit-text-model-info": "{suit_text_model_info}",
                    "suit-text-component-description": "{suit_text_component_description}",
                    "suit-text-component-version": "{suit_text_component_version}"
                }}
            }}
        }},
        "suit-integrated-payloads":
        {{
            "#file.bin": "file.bin"
        }}
    }}
}}

"""


def fuzz_full_path(data):
    """Fuzz multiple fields at once."""
    try:
        fdp = atheris.FuzzedDataProvider(data)
        fuzz_data = unsigned_envelope_json.format(
            suit_digest_algorithm_id="cose-alg-sha-256",
            suit_manifest_sequence_number=fdp.ConsumeUInt(16),
            suit_manifest_version=fdp.ConsumeUInt(16),
            suit_digest_bytes=fdp.ConsumeBytes(16).hex(),
            suit_text_vendor_name=fdp.ConsumeString(32),
            suit_text_component_version=fdp.ConsumeString(32),
            suit_text_component_description=fdp.ConsumeString(32),
            suit_text_model_info=fdp.ConsumeString(32),
            suit_text_vendor_domain=fdp.ConsumeString(32),
            suit_text_model_name=fdp.ConsumeString(32),
        )
        fuzz_object = json.loads(fuzz_data)
        env = SuitEnvelopeTagged.from_obj(fuzz_object)
        cbor1 = env.to_cbor()
        env2 = SuitEnvelopeTagged.from_cbor(cbor1)
        cbor2 = env2.to_cbor()
        assert cbor1.hex() == cbor2.hex()
    except ValueError:
        # ValueError is expected for some payloads since it's used by all suit-generator levels to report
        # not valid data.
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, fuzz_full_path)
    atheris.Fuzz()
