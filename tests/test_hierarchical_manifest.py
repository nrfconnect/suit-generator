#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for envelope.py implementation."""
import binascii
import os
import pathlib
import deepdiff
import pytest
import yaml
import json
from cryptography.hazmat.primitives import hashes
from suit_generator.envelope import SuitEnvelope
from suit_generator.suit.envelope import SuitEnvelopeTagged
from suit_generator.suit.types.keys import suit_integrated_dependencies

TEMP_DIRECTORY = pathlib.Path("test_test_data")

TEST_BINARY_ENVELOPE = (
    "d86ba4025827815824822f5820ef6346b6fa3dbbc6b1bac072319eeeab1acbc70a6d5e0e1c4b14f1a145688e3703590172a8010"
    "10201035894a30283824143410082414950816aa0a0af115ef2858afeb668b2e9c98241495008c1b59955e85fbc9e767bc29ce1"
    "b04d0458598e0c0114a201507617daa571fd5a858f94e28d735ce9f40250816aa0a0af115ef2858afeb668b2e9c90c0214a2015"
    "07617daa571fd5a858f94e28d735ce9f4025008c1b59955e85fbc9e767bc29ce1b04d0c820102010f020f01a300a001a002a007"
    "49860c820102070f0b0f0949860c820102070f0b0f115883960c0014a31569237261642e73756974035824822f5820162e59998"
    "0e3e9b65a4e52851592e15c05c4b10a0dfd0c407c7f6b2f3bda8cd30e1901911502030f070f0b0f14a31569236170702e737569"
    "74035824822f58202fa1276150be7c8ff9fd7e69da5478afe2254ea41d3d0447962a1e436e49a3570e19019f1502030f070f0b0"
    "f17822f582013715bae35ede2aeca791d1fcd87c96379c2fe8396d90e1c09566477f2dc442e05824149503f6a3a4dcdfa58c5ac"
    "cef9f584c4112469237261642e73756974590108d86ba3025827815824822f58202c245b791cba9274bf8dabebda417c124bee1"
    "96f495719bdb0ccdcea5017a7c10358caa80101020103586ba2028184414d4103451a0e054000451a000558000458548614a401"
    "507617daa571fd5a858f94e28d735ce9f40250816aa0a0af115ef2858afeb668b2e9c9035824822f58205f78c33274e43fa9de5"
    "659265c1d917e25c03722dcb0b8d27db8d5feaa8139530e04010f020f074382030f094382170211518614a11568237261642e62"
    "696e1502030f17822f5820cd54d1bbb4d891e79f3562d1e4e231afef4fa47f5f385546ddc87d9c83d23c440582414950816aa0a"
    "0af115ef2858afeb668b2e9c968237261642e62696e44deadbeef69236170702e73756974590108d86ba3025827815824822f58"
    "20d700dcc82c273faa2ec6956154a6730d4ff77c73579a7ae33b4288248fa06c7f0358caa80101020103586ba2028184414d410"
    "2451a0e0aa000451a0007f8000458548614a401507617daa571fd5a858f94e28d735ce9f4025008c1b59955e85fbc9e767bc29c"
    "e1b04d035824822f58200d5bc580d89a8f2b24b4cefacc724dbb969f8b13833a4fcc507b93d1bfe66c510e04010f020f0743820"
    "30f094382170211518614a11568236170702e62696e1502030f17822f58201d714f2dacd1880bcee0b7000d1c2485ae95e72d22"
    "f9e083e13b569e8f95e15c058241495008c1b59955e85fbc9e767bc29ce1b04d68236170702e62696e44c0ffee00"
)

TEST_JSON_STRING_UNSIGNED = """{
  "SUIT_Envelope_Tagged": {
    "suit-authentication-wrapper": {
      "SuitDigest": {
        "suit-digest-algorithm-id": "cose-alg-sha-256"
      }
    },
    "suit-manifest": {
      "suit-manifest-version": 1,
      "suit-manifest-sequence-number": 1,
      "suit-common": {
        "suit-components": [
          [
            "C",
            0
          ],
          [
            "I",
            {
              "RFC4122_UUID": {
                "namespace": "nordicsemi.com",
                "name": "nRF54H20_sample_rad"
              }
            }
          ],
          [
            "I",
            {
              "RFC4122_UUID": {
                "namespace": "nordicsemi.com",
                "name": "nRF54H20_sample_app"
              }
            }
          ]
        ],
        "suit-shared-sequence": [
          {
            "suit-directive-set-component-index": 1
          },
          {
            "suit-directive-override-parameters": {
              "suit-parameter-vendor-identifier": {
                "RFC4122_UUID": "nordicsemi.com"
              },
              "suit-parameter-class-identifier": {
                "RFC4122_UUID": {
                  "namespace": "nordicsemi.com",
                  "name": "nRF54H20_sample_rad"
                }
              }
            }
          },
          {
            "suit-directive-set-component-index": 2
          },
          {
            "suit-directive-override-parameters": {
              "suit-parameter-vendor-identifier": {
                "RFC4122_UUID": "nordicsemi.com"
              },
              "suit-parameter-class-identifier": {
                "RFC4122_UUID": {
                  "namespace": "nordicsemi.com",
                  "name": "nRF54H20_sample_app"
                }
              }
            }
          },
          {
            "suit-directive-set-component-index": [
              1,
              2
            ]
          },
          {
            "suit-condition-vendor-identifier": [
              "suit-send-record-success",
              "suit-send-record-failure",
              "suit-send-sysinfo-success",
              "suit-send-sysinfo-failure"
            ]
          },
          {
            "suit-condition-class-identifier": [
              "suit-send-record-success",
              "suit-send-record-failure",
              "suit-send-sysinfo-success",
              "suit-send-sysinfo-failure"
            ]
          }
        ],
        "suit-dependencies": {
          "0": {},
          "1": {},
          "2": {}
        }
      },
      "suit-validate": [
        {
          "suit-directive-set-component-index": [
            1,
            2
          ]
        },
        {
          "suit-condition-dependency-integrity": [
            "suit-send-record-success",
            "suit-send-record-failure",
            "suit-send-sysinfo-success",
            "suit-send-sysinfo-failure"
          ]
        },
        {
          "suit-directive-process-dependency": [
            "suit-send-record-success",
            "suit-send-record-failure",
            "suit-send-sysinfo-success",
            "suit-send-sysinfo-failure"
          ]
        }
      ],
      "suit-invoke": [
        {
          "suit-directive-set-component-index": [
            1,
            2
          ]
        },
        {
          "suit-condition-dependency-integrity": [
            "suit-send-record-success",
            "suit-send-record-failure",
            "suit-send-sysinfo-success",
            "suit-send-sysinfo-failure"
          ]
        },
        {
          "suit-directive-process-dependency": [
            "suit-send-record-success",
            "suit-send-record-failure",
            "suit-send-sysinfo-success",
            "suit-send-sysinfo-failure"
          ]
        }
      ],
      "suit-install": [
        {
          "suit-directive-set-component-index": 0
        },
        {
          "suit-directive-override-parameters": {
            "suit-parameter-uri": "#rad.suit",
            "suit-parameter-image-digest": {
              "suit-digest-algorithm-id": "cose-alg-sha-256",
              "suit-digest-bytes": {
                "envelope": {
                  "SUIT_Envelope_Tagged": {
                    "suit-authentication-wrapper": {
                      "SuitDigest": {
                        "suit-digest-algorithm-id": "cose-alg-sha-256"
                      }
                    },
                    "suit-manifest": {
                      "suit-manifest-version": 1,
                      "suit-manifest-sequence-number": 1,
                      "suit-common": {
                        "suit-components": [
                          [
                            "M",
                            3,
                            235225088,
                            350208
                          ]
                        ],
                        "suit-shared-sequence": [
                          {
                            "suit-directive-override-parameters": {
                              "suit-parameter-vendor-identifier": {
                                "RFC4122_UUID": "nordicsemi.com"
                              },
                              "suit-parameter-class-identifier": {
                                "RFC4122_UUID": {
                                  "namespace": "nordicsemi.com",
                                  "name": "nRF54H20_sample_rad"
                                }
                              },
                              "suit-parameter-image-digest": {
                                "suit-digest-algorithm-id": "cose-alg-sha-256",
                                "suit-digest-bytes": {
                                  "file": "rad.bin"
                                }
                              },
                              "suit-parameter-image-size": {
                                "file": "rad.bin"
                              }
                            }
                          },
                          {
                            "suit-condition-vendor-identifier": [
                              "suit-send-record-success",
                              "suit-send-record-failure",
                              "suit-send-sysinfo-success",
                              "suit-send-sysinfo-failure"
                            ]
                          },
                          {
                            "suit-condition-class-identifier": [
                              "suit-send-record-success",
                              "suit-send-record-failure",
                              "suit-send-sysinfo-success",
                              "suit-send-sysinfo-failure"
                            ]
                          }
                        ]
                      },
                      "suit-validate": [
                        {
                          "suit-condition-image-match": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure"
                          ]
                        }
                      ],
                      "suit-invoke": [
                        {
                          "suit-directive-invoke": [
                            "suit-send-record-failure"
                          ]
                        }
                      ],
                      "suit-install": [
                        {
                          "suit-directive-override-parameters": {
                            "suit-parameter-uri": "#rad.bin"
                          }
                        },
                        {
                          "suit-directive-fetch": [
                            "suit-send-record-failure"
                          ]
                        },
                        {
                          "suit-condition-image-match": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure"
                          ]
                        }
                      ],
                      "suit-text": {
                        "suit-digest-algorithm-id": "cose-alg-sha-256"
                      },
                      "suit-manifest-component-id": [
                        "I",
                        {
                          "RFC4122_UUID": {
                            "namespace": "nordicsemi.com",
                            "name": "nRF54H20_sample_rad"
                          }
                        }
                      ]
                    },
                    "suit-text": {
                      "en": {
                        "[\\"M\\", 3, 235225088, 350208]": {
                          "suit-text-vendor-name": "Nordic Semiconductor ASA",
                          "suit-text-model-name": "nRF54H20_cpurad",
                          "suit-text-vendor-domain": "nordicsemi.com",
                          "suit-text-model-info": "The nRF54H20 radio core",
                          "suit-text-component-description": "Sample radio core FW",
                          "suit-text-component-version": "v1.0.0"
                        }
                      }
                    },
                    "suit-integrated-payloads": {
                      "#rad.bin": "rad.bin"
                    }
                  }
                }
              }
            },
            "suit-parameter-image-size": {
              "envelope": {
                "SUIT_Envelope_Tagged": {
                  "suit-authentication-wrapper": {
                    "SuitDigest": {
                      "suit-digest-algorithm-id": "cose-alg-sha-256"
                    }
                  },
                  "suit-manifest": {
                    "suit-manifest-version": 1,
                    "suit-manifest-sequence-number": 1,
                    "suit-common": {
                      "suit-components": [
                        [
                          "M",
                          3,
                          235225088,
                          350208
                        ]
                      ],
                      "suit-shared-sequence": [
                        {
                          "suit-directive-override-parameters": {
                            "suit-parameter-vendor-identifier": {
                              "RFC4122_UUID": "nordicsemi.com"
                            },
                            "suit-parameter-class-identifier": {
                              "RFC4122_UUID": {
                                "namespace": "nordicsemi.com",
                                "name": "nRF54H20_sample_rad"
                              }
                            },
                            "suit-parameter-image-digest": {
                              "suit-digest-algorithm-id": "cose-alg-sha-256",
                              "suit-digest-bytes": {
                                "file": "rad.bin"
                              }
                            },
                            "suit-parameter-image-size": {
                              "file": "rad.bin"
                            }
                          }
                        },
                        {
                          "suit-condition-vendor-identifier": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure"
                          ]
                        },
                        {
                          "suit-condition-class-identifier": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure"
                          ]
                        }
                      ]
                    },
                    "suit-validate": [
                      {
                        "suit-condition-image-match": [
                          "suit-send-record-success",
                          "suit-send-record-failure",
                          "suit-send-sysinfo-success",
                          "suit-send-sysinfo-failure"
                        ]
                      }
                    ],
                    "suit-invoke": [
                      {
                        "suit-directive-invoke": [
                          "suit-send-record-failure"
                        ]
                      }
                    ],
                    "suit-install": [
                      {
                        "suit-directive-override-parameters": {
                          "suit-parameter-uri": "#rad.bin"
                        }
                      },
                      {
                        "suit-directive-fetch": [
                          "suit-send-record-failure"
                        ]
                      },
                      {
                        "suit-condition-image-match": [
                          "suit-send-record-success",
                          "suit-send-record-failure",
                          "suit-send-sysinfo-success",
                          "suit-send-sysinfo-failure"
                        ]
                      }
                    ],
                    "suit-text": {
                      "suit-digest-algorithm-id": "cose-alg-sha-256"
                    },
                    "suit-manifest-component-id": [
                      "I",
                      {
                        "RFC4122_UUID": {
                          "namespace": "nordicsemi.com",
                          "name": "nRF54H20_sample_rad"
                        }
                      }
                    ]
                  },
                  "suit-text": {
                    "en": {
                      "[\\"M\\", 3, 235225088, 350208]": {
                        "suit-text-vendor-name": "Nordic Semiconductor ASA",
                        "suit-text-model-name": "nRF54H20_cpurad",
                        "suit-text-vendor-domain": "nordicsemi.com",
                        "suit-text-model-info": "The nRF54H20 radio core",
                        "suit-text-component-description": "Sample radio core FW",
                        "suit-text-component-version": "v1.0.0"
                      }
                    }
                  },
                  "suit-integrated-payloads": {
                    "#rad.bin": "rad.bin"
                  }
                }
              }
            }
          }
        },
        {
          "suit-directive-fetch": [
            "suit-send-record-failure"
          ]
        },
        {
          "suit-condition-image-match": [
            "suit-send-record-success",
            "suit-send-record-failure",
            "suit-send-sysinfo-success",
            "suit-send-sysinfo-failure"
          ]
        },
        {
          "suit-condition-dependency-integrity": [
            "suit-send-record-success",
            "suit-send-record-failure",
            "suit-send-sysinfo-success",
            "suit-send-sysinfo-failure"
          ]
        },
        {
          "suit-directive-process-dependency": [
            "suit-send-record-success",
            "suit-send-record-failure",
            "suit-send-sysinfo-success",
            "suit-send-sysinfo-failure"
          ]
        },
        {
          "suit-directive-override-parameters": {
            "suit-parameter-uri": "#app.suit",
            "suit-parameter-image-digest": {
              "suit-digest-algorithm-id": "cose-alg-sha-256",
              "suit-digest-bytes": {
                "envelope": {
                  "SUIT_Envelope_Tagged": {
                    "suit-authentication-wrapper": {
                      "SuitDigest": {
                        "suit-digest-algorithm-id": "cose-alg-sha-256"
                      }
                    },
                    "suit-manifest": {
                      "suit-manifest-version": 1,
                      "suit-manifest-sequence-number": 1,
                      "suit-common": {
                        "suit-components": [
                          [
                            "M",
                            2,
                            235577344,
                            522240
                          ]
                        ],
                        "suit-shared-sequence": [
                          {
                            "suit-directive-override-parameters": {
                              "suit-parameter-vendor-identifier": {
                                "RFC4122_UUID": "nordicsemi.com"
                              },
                              "suit-parameter-class-identifier": {
                                "RFC4122_UUID": {
                                  "namespace": "nordicsemi.com",
                                  "name": "nRF54H20_sample_app"
                                }
                              },
                              "suit-parameter-image-digest": {
                                "suit-digest-algorithm-id": "cose-alg-sha-256",
                                "suit-digest-bytes": {
                                  "file": "app.bin"
                                }
                              },
                              "suit-parameter-image-size": {
                                "file": "app.bin"
                              }
                            }
                          },
                          {
                            "suit-condition-vendor-identifier": [
                              "suit-send-record-success",
                              "suit-send-record-failure",
                              "suit-send-sysinfo-success",
                              "suit-send-sysinfo-failure"
                            ]
                          },
                          {
                            "suit-condition-class-identifier": [
                              "suit-send-record-success",
                              "suit-send-record-failure",
                              "suit-send-sysinfo-success",
                              "suit-send-sysinfo-failure"
                            ]
                          }
                        ]
                      },
                      "suit-validate": [
                        {
                          "suit-condition-image-match": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure"
                          ]
                        }
                      ],
                      "suit-invoke": [
                        {
                          "suit-directive-invoke": [
                            "suit-send-record-failure"
                          ]
                        }
                      ],
                      "suit-install": [
                        {
                          "suit-directive-override-parameters": {
                            "suit-parameter-uri": "#app.bin"
                          }
                        },
                        {
                          "suit-directive-fetch": [
                            "suit-send-record-failure"
                          ]
                        },
                        {
                          "suit-condition-image-match": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure"
                          ]
                        }
                      ],
                      "suit-text": {
                        "suit-digest-algorithm-id": "cose-alg-sha-256"
                      },
                      "suit-manifest-component-id": [
                        "I",
                        {
                          "RFC4122_UUID": {
                            "namespace": "nordicsemi.com",
                            "name": "nRF54H20_sample_app"
                          }
                        }
                      ]
                    },
                    "suit-text": {
                      "en": {
                        "[\\"M\\", 2, 235577344, 522240]": {
                          "suit-text-vendor-name": "Nordic Semiconductor ASA",
                          "suit-text-model-name": "nRF54H20_cpuapp",
                          "suit-text-vendor-domain": "nordicsemi.com",
                          "suit-text-model-info": "The nRF54H20 application core",
                          "suit-text-component-description": "Sample application core FW",
                          "suit-text-component-version": "v1.0.0"
                        }
                      }
                    },
                    "suit-integrated-payloads": {
                      "#app.bin": "app.bin"
                    }
                  }
                }
              }
            },
            "suit-parameter-image-size": {
              "envelope": {
                "SUIT_Envelope_Tagged": {
                  "suit-authentication-wrapper": {
                    "SuitDigest": {
                      "suit-digest-algorithm-id": "cose-alg-sha-256"
                    }
                  },
                  "suit-manifest": {
                    "suit-manifest-version": 1,
                    "suit-manifest-sequence-number": 1,
                    "suit-common": {
                      "suit-components": [
                        [
                          "M",
                          2,
                          235577344,
                          522240
                        ]
                      ],
                      "suit-shared-sequence": [
                        {
                          "suit-directive-override-parameters": {
                            "suit-parameter-vendor-identifier": {
                              "RFC4122_UUID": "nordicsemi.com"
                            },
                            "suit-parameter-class-identifier": {
                              "RFC4122_UUID": {
                                "namespace": "nordicsemi.com",
                                "name": "nRF54H20_sample_app"
                              }
                            },
                            "suit-parameter-image-digest": {
                              "suit-digest-algorithm-id": "cose-alg-sha-256",
                              "suit-digest-bytes": {
                                "file": "app.bin"
                              }
                            },
                            "suit-parameter-image-size": {
                              "file": "app.bin"
                            }
                          }
                        },
                        {
                          "suit-condition-vendor-identifier": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure"
                          ]
                        },
                        {
                          "suit-condition-class-identifier": [
                            "suit-send-record-success",
                            "suit-send-record-failure",
                            "suit-send-sysinfo-success",
                            "suit-send-sysinfo-failure"
                          ]
                        }
                      ]
                    },
                    "suit-validate": [
                      {
                        "suit-condition-image-match": [
                          "suit-send-record-success",
                          "suit-send-record-failure",
                          "suit-send-sysinfo-success",
                          "suit-send-sysinfo-failure"
                        ]
                      }
                    ],
                    "suit-invoke": [
                      {
                        "suit-directive-invoke": [
                          "suit-send-record-failure"
                        ]
                      }
                    ],
                    "suit-install": [
                      {
                        "suit-directive-override-parameters": {
                          "suit-parameter-uri": "#app.bin"
                        }
                      },
                      {
                        "suit-directive-fetch": [
                          "suit-send-record-failure"
                        ]
                      },
                      {
                        "suit-condition-image-match": [
                          "suit-send-record-success",
                          "suit-send-record-failure",
                          "suit-send-sysinfo-success",
                          "suit-send-sysinfo-failure"
                        ]
                      }
                    ],
                    "suit-text": {
                      "suit-digest-algorithm-id": "cose-alg-sha-256"
                    },
                    "suit-manifest-component-id": [
                      "I",
                      {
                        "RFC4122_UUID": {
                          "namespace": "nordicsemi.com",
                          "name": "nRF54H20_sample_app"
                        }
                      }
                    ]
                  },
                  "suit-text": {
                    "en": {
                      "[\\"M\\", 2, 235577344, 522240]": {
                        "suit-text-vendor-name": "Nordic Semiconductor ASA",
                        "suit-text-model-name": "nRF54H20_cpuapp",
                        "suit-text-vendor-domain": "nordicsemi.com",
                        "suit-text-model-info": "The nRF54H20 application core",
                        "suit-text-component-description": "Sample application core FW",
                        "suit-text-component-version": "v1.0.0"
                      }
                    }
                  },
                  "suit-integrated-payloads": {
                    "#app.bin": "app.bin"
                  }
                }
              }
            }
          }
        },
        {
          "suit-directive-fetch": [
            "suit-send-record-failure"
          ]
        },
        {
          "suit-condition-image-match": [
            "suit-send-record-success",
            "suit-send-record-failure",
            "suit-send-sysinfo-success",
            "suit-send-sysinfo-failure"
          ]
        },
        {
          "suit-condition-dependency-integrity": [
            "suit-send-record-success",
            "suit-send-record-failure",
            "suit-send-sysinfo-success",
            "suit-send-sysinfo-failure"
          ]
        },
        {
          "suit-directive-process-dependency": [
            "suit-send-record-success",
            "suit-send-record-failure",
            "suit-send-sysinfo-success",
            "suit-send-sysinfo-failure"
          ]
        }
      ],
      "suit-text": {
        "suit-digest-algorithm-id": "cose-alg-sha-256"
      },
      "suit-manifest-component-id": [
        "I",
        {
          "RFC4122_UUID": {
            "namespace": "nordicsemi.com",
            "name": "nRF54H20_sample_root"
          }
        }
      ]
    },
    "suit-text": {
      "en": {
        "[\\"C\\", 0]": {
          "suit-text-vendor-name": "Nordic Semiconductor ASA",
          "suit-text-model-name": "nRF54H20",
          "suit-text-vendor-domain": "nordicsemi.com",
          "suit-text-model-info": "The nRF54H20 root manifest",
          "suit-text-component-description": "Sample root manifest",
          "suit-text-component-version": "v1.0.0"
        }
      }
    },
    "suit-integrated-dependencies": {
      "#rad.suit": {
        "SUIT_Envelope_Tagged": {
          "suit-authentication-wrapper": {
            "SuitDigest": {
              "suit-digest-algorithm-id": "cose-alg-sha-256"
            }
          },
          "suit-manifest": {
            "suit-manifest-version": 1,
            "suit-manifest-sequence-number": 1,
            "suit-common": {
              "suit-components": [
                [
                  "M",
                  3,
                  235225088,
                  350208
                ]
              ],
              "suit-shared-sequence": [
                {
                  "suit-directive-override-parameters": {
                    "suit-parameter-vendor-identifier": {
                      "RFC4122_UUID": "nordicsemi.com"
                    },
                    "suit-parameter-class-identifier": {
                      "RFC4122_UUID": {
                        "namespace": "nordicsemi.com",
                        "name": "nRF54H20_sample_rad"
                      }
                    },
                    "suit-parameter-image-digest": {
                      "suit-digest-algorithm-id": "cose-alg-sha-256",
                      "suit-digest-bytes": {
                        "file": "rad.bin"
                      }
                    },
                    "suit-parameter-image-size": {
                      "file": "rad.bin"
                    }
                  }
                },
                {
                  "suit-condition-vendor-identifier": [
                    "suit-send-record-success",
                    "suit-send-record-failure",
                    "suit-send-sysinfo-success",
                    "suit-send-sysinfo-failure"
                  ]
                },
                {
                  "suit-condition-class-identifier": [
                    "suit-send-record-success",
                    "suit-send-record-failure",
                    "suit-send-sysinfo-success",
                    "suit-send-sysinfo-failure"
                  ]
                }
              ]
            },
            "suit-validate": [
              {
                "suit-condition-image-match": [
                  "suit-send-record-success",
                  "suit-send-record-failure",
                  "suit-send-sysinfo-success",
                  "suit-send-sysinfo-failure"
                ]
              }
            ],
            "suit-invoke": [
              {
                "suit-directive-invoke": [
                  "suit-send-record-failure"
                ]
              }
            ],
            "suit-install": [
              {
                "suit-directive-override-parameters": {
                  "suit-parameter-uri": "#rad.bin"
                }
              },
              {
                "suit-directive-fetch": [
                  "suit-send-record-failure"
                ]
              },
              {
                "suit-condition-image-match": [
                  "suit-send-record-success",
                  "suit-send-record-failure",
                  "suit-send-sysinfo-success",
                  "suit-send-sysinfo-failure"
                ]
              }
            ],
            "suit-text": {
              "suit-digest-algorithm-id": "cose-alg-sha-256"
            },
            "suit-manifest-component-id": [
              "I",
              {
                "RFC4122_UUID": {
                  "namespace": "nordicsemi.com",
                  "name": "nRF54H20_sample_rad"
                }
              }
            ]
          },
          "suit-text": {
            "en": {
              "[\\"M\\", 3, 235225088, 350208]": {
                "suit-text-vendor-name": "Nordic Semiconductor ASA",
                "suit-text-model-name": "nRF54H20_cpurad",
                "suit-text-vendor-domain": "nordicsemi.com",
                "suit-text-model-info": "The nRF54H20 radio core",
                "suit-text-component-description": "Sample radio core FW",
                "suit-text-component-version": "v1.0.0"
              }
            }
          },
          "suit-integrated-payloads": {
            "#rad.bin": "rad.bin"
          }
        }
      },
      "#app.suit": {
        "SUIT_Envelope_Tagged": {
          "suit-authentication-wrapper": {
            "SuitDigest": {
              "suit-digest-algorithm-id": "cose-alg-sha-256"
            }
          },
          "suit-manifest": {
            "suit-manifest-version": 1,
            "suit-manifest-sequence-number": 1,
            "suit-common": {
              "suit-components": [
                [
                  "M",
                  2,
                  235577344,
                  522240
                ]
              ],
              "suit-shared-sequence": [
                {
                  "suit-directive-override-parameters": {
                    "suit-parameter-vendor-identifier": {
                      "RFC4122_UUID": "nordicsemi.com"
                    },
                    "suit-parameter-class-identifier": {
                      "RFC4122_UUID": {
                        "namespace": "nordicsemi.com",
                        "name": "nRF54H20_sample_app"
                      }
                    },
                    "suit-parameter-image-digest": {
                      "suit-digest-algorithm-id": "cose-alg-sha-256",
                      "suit-digest-bytes": {
                        "file": "app.bin"
                      }
                    },
                    "suit-parameter-image-size": {
                      "file": "app.bin"
                    }
                  }
                },
                {
                  "suit-condition-vendor-identifier": [
                    "suit-send-record-success",
                    "suit-send-record-failure",
                    "suit-send-sysinfo-success",
                    "suit-send-sysinfo-failure"
                  ]
                },
                {
                  "suit-condition-class-identifier": [
                    "suit-send-record-success",
                    "suit-send-record-failure",
                    "suit-send-sysinfo-success",
                    "suit-send-sysinfo-failure"
                  ]
                }
              ]
            },
            "suit-validate": [
              {
                "suit-condition-image-match": [
                  "suit-send-record-success",
                  "suit-send-record-failure",
                  "suit-send-sysinfo-success",
                  "suit-send-sysinfo-failure"
                ]
              }
            ],
            "suit-invoke": [
              {
                "suit-directive-invoke": [
                  "suit-send-record-failure"
                ]
              }
            ],
            "suit-install": [
              {
                "suit-directive-override-parameters": {
                  "suit-parameter-uri": "#app.bin"
                }
              },
              {
                "suit-directive-fetch": [
                  "suit-send-record-failure"
                ]
              },
              {
                "suit-condition-image-match": [
                  "suit-send-record-success",
                  "suit-send-record-failure",
                  "suit-send-sysinfo-success",
                  "suit-send-sysinfo-failure"
                ]
              }
            ],
            "suit-text": {
              "suit-digest-algorithm-id": "cose-alg-sha-256"
            },
            "suit-manifest-component-id": [
              "I",
              {
                "RFC4122_UUID": {
                  "namespace": "nordicsemi.com",
                  "name": "nRF54H20_sample_app"
                }
              }
            ]
          },
          "suit-text": {
            "en": {
              "[\\"M\\", 2, 235577344, 522240]": {
                "suit-text-vendor-name": "Nordic Semiconductor ASA",
                "suit-text-model-name": "nRF54H20_cpuapp",
                "suit-text-vendor-domain": "nordicsemi.com",
                "suit-text-model-info": "The nRF54H20 application core",
                "suit-text-component-description": "Sample application core FW",
                "suit-text-component-version": "v1.0.0"
              }
            }
          },
          "suit-integrated-payloads": {
            "#app.bin": "app.bin"
          }
        }
      }
    }
  }
}
"""

TEST_YAML_STRING_MULTILEVEL_HIERARCHY = """SUIT_Dependent_Manifests:
    top_envelope: &nordic_top
      SUIT_Dependent_Manifests:
        sysctrl: &sysctrl
            SUIT_Envelope_Tagged:
              suit-authentication-wrapper:
                SuitDigest:
                  suit-digest-algorithm-id: cose-alg-sha-256
              suit-manifest:
                suit-manifest-version: 1
                suit-manifest-sequence-number: 1
                suit-common:
                  suit-components:
                  - - SOC_SPEC
                    - 1
                  - - CAND_IMG
                    - 0
                  suit-shared-sequence:
                  - suit-directive-set-component-index: 0
                  - suit-directive-override-parameters:
                      suit-parameter-vendor-identifier:
                        RFC4122_UUID:
                          name: nordicsemi.com
                      suit-parameter-class-identifier:
                        RFC4122_UUID:
                          namespace: nordicsemi.com
                          name: nRF54H20_sys
                suit-install:
                - suit-directive-set-component-index: 1
                - suit-directive-override-parameters:
                    suit-parameter-uri: '#sysctrl'
                - suit-directive-fetch:
                  - suit-send-record-failure
                - suit-directive-set-component-index: 0
                - suit-directive-override-parameters:
                    suit-parameter-source-component: 1
                - suit-directive-copy:
                  - suit-send-record-failure
                suit-manifest-component-id:
                - INSTLD_MFST
                - RFC4122_UUID:
                    namespace: nordicsemi.com
                    name: nRF54H20_sys
              suit-integrated-payloads:
                '#sysctrl': app.bin

      SUIT_Envelope_Tagged:
        suit-authentication-wrapper:
          SuitDigest:
            suit-digest-algorithm-id: cose-alg-sha-256
        suit-manifest:
          suit-manifest-version: 1
          suit-manifest-sequence-number: 1
          suit-common:
            suit-components:
            - - CAND_MFST
              - 0
            - - INSTLD_MFST
              - RFC4122_UUID:
                  namespace: nordicsemi.com
                  name: nRF54H20_sys
            suit-shared-sequence:
            - suit-directive-set-component-index: 1
            - suit-directive-override-parameters:
                suit-parameter-class-identifier:
                  RFC4122_UUID:
                    namespace: nordicsemi.com
                    name: nRF54H20_sys
            suit-dependencies:
              # Key is the index of suit-components that describe the dependency manifest
              "0": {}
              "1": {}
              "2": {}
          suit-validate:
          - suit-directive-set-component-index: 1
          - suit-directive-process-dependency:
            - suit-send-record-success
            - suit-send-record-failure
            - suit-send-sysinfo-success
            - suit-send-sysinfo-failure
          suit-load:
          - suit-directive-set-component-index: 1
          - suit-directive-process-dependency:
            - suit-send-record-success
            - suit-send-record-failure
            - suit-send-sysinfo-success
            - suit-send-sysinfo-failure
          suit-invoke:
          - suit-directive-set-component-index: 1
          - suit-directive-process-dependency:
            - suit-send-record-success
            - suit-send-record-failure
            - suit-send-sysinfo-success
            - suit-send-sysinfo-failure
          suit-install:
          - suit-directive-set-component-index: 0
          - suit-directive-override-parameters:
              suit-parameter-uri: '#sysctrl'
          - suit-directive-fetch:
            - suit-send-record-failure
          - suit-directive-process-dependency:
            - suit-send-record-success
            - suit-send-record-failure
            - suit-send-sysinfo-success
            - suit-send-sysinfo-failure
          suit-manifest-component-id:
          - INSTLD_MFST
          - RFC4122_UUID:
              namespace: nordicsemi.com
              name: nRF54H20_nordic_top
        suit-integrated-dependencies:
          '#sysctrl': *sysctrl

SUIT_Envelope_Tagged:
  suit-authentication-wrapper:
    SuitDigest:
      suit-digest-algorithm-id: cose-alg-sha-256
  suit-manifest:
    suit-manifest-version: 1
    suit-manifest-sequence-number: 1
    suit-common:
      suit-components:
      - - CAND_MFST
        - 0
      - - INSTLD_MFST
        - RFC4122_UUID:
            namespace: nordicsemi.com
            name: nRF54H20_nordic_top
      suit-shared-sequence:
      - suit-directive-set-component-index: 1
      - suit-directive-override-parameters:
          suit-parameter-vendor-identifier:
            RFC4122_UUID: nordicsemi.com
          suit-parameter-class-identifier:
            RFC4122_UUID:
              namespace: nordicsemi.com
              name: nRF54H20_nordic_top
      suit-dependencies:
        # Key is the index of suit-components that describe the dependency manifest
        "0": {}
        "1": {}

    suit-install:
    - suit-directive-set-component-index: 0
    - suit-directive-override-parameters:
        suit-parameter-uri: '#top'
    - suit-directive-process-dependency:
      - suit-send-record-success
      - suit-send-record-failure
      - suit-send-sysinfo-success
      - suit-send-sysinfo-failure
    suit-manifest-component-id:
    - INSTLD_MFST
    - RFC4122_UUID:
        namespace: nordicsemi.com
        name: nRF54H20_sample_root
  suit-integrated-dependencies:
    '#top': *nordic_top"""

TEST_YAML_STRING_UNSIGNED_ALIASES = """SUIT_Dependent_Manifests:
    app_envelope: &app
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
            en:
              '["M", 2, 235577344, 522240]':
                suit-text-vendor-name: Nordic Semiconductor ASA
                suit-text-model-name: nRF54H20_cpuapp
                suit-text-vendor-domain: nordicsemi.com
                suit-text-model-info: The nRF54H20 application core
                suit-text-component-description: Sample application core FW
                suit-text-component-version: v1.0.0
          suit-integrated-payloads:
            '#app.bin': app.bin
    radio_envelope: &rad
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
            en:
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
    en:
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

TEST_YAML_STRING_UNSIGNED_ALIASES_AND_BINARY = """SUIT_Dependent_Manifests:
    app_envelope: &app app.suit
    radio_envelope: &rad
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
            en:
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
    en:
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

TEST_BINARY_SUB_ENVELOPE_APP = (
    "D86BA3025827815824822F58201D15A6F8E2026C28E1E165D203523F80D9AC2DC5E92486FA88BEB02D595494AC0358CAA801010"
    "20103586BA2028184414D4102451A0E0AA000451A0007F8000458548614A401507617DAA571FD5A858F94E28D735CE9F4025008"
    "C1B59955E85FBC9E767BC29CE1B04D035824822F58200D5BC580D89A8F2B24B4CEFACC724DBB969F8B13833A4FCC507B93D1BFE"
    "66C510E04010F020F074382030F094382170211518614A11568236170702E62696E1502030F17822F5820749FCAD1CEAF733132"
    "8A046DBDF8C76B9F515931154C54087CF057F43E0EF59F058241495008C1B59955E85FBC9E767BC29CE1B04D68236170702E626"
    "96E44C0FFEE00"
)


@pytest.fixture
def setup_and_teardown(tmp_path_factory):
    """Create and cleanup environment."""
    # Setup environment
    #   - create temp directory
    #   - create input json files
    #   - create binary files
    start_directory = os.getcwd()
    path = tmp_path_factory.mktemp(TEMP_DIRECTORY)
    print(f"temp {path}")
    os.chdir(path)
    with open("envelope_1.yaml", "w") as fh:
        fh.write(TEST_YAML_STRING_UNSIGNED_ALIASES)
    with open("envelope_2.yaml", "w") as fh:
        fh.write(TEST_YAML_STRING_UNSIGNED_ALIASES_AND_BINARY)
    with open("envelope_3.yaml", "w") as fh:
        fh.write(TEST_YAML_STRING_MULTILEVEL_HIERARCHY)
    with open("envelope_1.json", "w") as fh:
        fh.write(TEST_JSON_STRING_UNSIGNED)
    with open("rad.bin", "wb") as fh:
        fh.write(b"\xde\xad\xbe\xef")
    with open("app.bin", "wb") as fh:
        fh.write(b"\xc0\xff\xee\x00")
    with open("input_envelope_1.suit", "wb") as fh:
        fh.write(binascii.a2b_hex(TEST_BINARY_ENVELOPE))
    with open("app.suit", "wb") as fh:
        fh.write(binascii.a2b_hex(TEST_BINARY_SUB_ENVELOPE_APP))
    yield
    # Cleanup environment
    #   - remove temp directory
    os.chdir(start_directory)


@pytest.mark.parametrize(
    "input_data", [pathlib.Path("envelope_1.json"), pathlib.Path("envelope_1.yaml"), pathlib.Path("envelope_2.yaml")]
)
def test_envelope_creation(setup_and_teardown, input_data):
    """Check if is possible to create binary envelope from hierarchical input configuration."""
    envelope = SuitEnvelope()
    input_type = input_data.suffix[1:]
    envelope.load(input_data, input_type=input_type)
    envelope.dump(f"{pathlib.Path(input_data).stem}.suit", output_type="suit", parse_hierarchy=True)
    envelope.load(f"{pathlib.Path(input_data).stem}.suit", input_type="suit")
    # ensure that digest of dependent manifest is calculated properly
    # get values stored in the root manifest
    rad_sub_manifest_digest = envelope._envelope["SUIT_Envelope_Tagged"]["suit-manifest"]["suit-install"][1][
        "suit-directive-override-parameters"
    ]["suit-parameter-image-digest"]["suit-digest-bytes"]
    app_sub_manifest_digest = envelope._envelope["SUIT_Envelope_Tagged"]["suit-manifest"]["suit-install"][6][
        "suit-directive-override-parameters"
    ]["suit-parameter-image-digest"]["suit-digest-bytes"]
    # parse dependent manifest
    e1_rad = SuitEnvelopeTagged.from_cbor(
        binascii.a2b_hex(envelope._envelope["SUIT_Envelope_Tagged"]["suit-integrated-dependencies"]["#rad.suit"])
    )
    e2_app = SuitEnvelopeTagged.from_cbor(
        binascii.a2b_hex(envelope._envelope["SUIT_Envelope_Tagged"]["suit-integrated-dependencies"]["#app.suit"])
    )
    # get digests stored in the dependent manifests
    rad_root_digest = e1_rad.get_digest().SuitDigestRaw[1].SuitDigestBytes.hex()
    app_root_digest = e2_app.get_digest().SuitDigestRaw[1].SuitDigestBytes.hex()
    # ensure that root values are equal to digest stored in the sub-manifest
    assert rad_sub_manifest_digest == rad_root_digest
    assert app_sub_manifest_digest == app_root_digest


def calculate_hash(data):
    """Calculate sha256 for the input data."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def exclude_obj_callback(obj, path):
    """Exclude filter to use with deepdiff."""
    # filter out SUIT_Dependent_Manifests contains two elements (expected case but with renamed anchors)
    return True if "SUIT_Dependent_Manifests" in path and len(obj) == 2 else False


@pytest.mark.parametrize(
    "input_data", [pathlib.Path("envelope_1.json"), pathlib.Path("envelope_1.yaml"), pathlib.Path("envelope_2.yaml")]
)
def test_envelope_unsigned_creation_and_parsing(setup_and_teardown, input_data):
    """Test recreation of configuration files and binary envelopes."""
    envelope = SuitEnvelope()
    # create envelope_1
    input_type = input_data.suffix[1:]
    input_data_copy = f"{input_data.stem}_copy.{input_type}"
    binary_envelope = f"{input_data.stem}.suit"
    binary_envelope_copy = f"{input_data.stem}_copy.suit"

    envelope.load(input_data, input_type=input_type)
    envelope.dump(binary_envelope, output_type="suit")
    # parse envelope_1
    envelope.load(binary_envelope, input_type="suit")
    envelope.dump(input_data_copy, output_type=input_type, parse_hierarchy=True)
    # create envelope_1_copy based on new input file
    envelope.load(input_data_copy, input_type=input_type)
    envelope.dump(binary_envelope_copy, output_type="suit")
    # compare input and output files
    with open(input_data) as fh_1, open(input_data_copy) as fh_2:
        if input_type == "yaml":
            d1 = yaml.load(fh_1.read(), Loader=yaml.SafeLoader)
            d2 = yaml.load(fh_2.read(), Loader=yaml.SafeLoader)
        elif input_type == "json":
            d1 = json.loads(fh_1.read())
            d2 = json.loads(fh_2.read())
        else:
            raise TypeError(f"{input_type} is not supported")
        diff = deepdiff.DeepDiff(
            d2,
            d1,
            exclude_regex_paths=[  # exclude data replaced/removed/added by design
                r"root(\[.*\])*\['raw'\]",  # added only to the output envelope
                r"root(\[.*\])*\['suit-digest-bytes'\]",  # added only to the output envelope
                r"root(\[.*\])*\['RFC4122_UUID'\]",  # replaced in the output envelope
                r"root(\[.*\])*\['envelope'\]",  # replaced by raw value
                r"root(\[.*\])*\['suit-integrated-dependencies'\]",  # replaced by raw value
                r"root(\[.*\])*\['suit-integrated-payloads'\]",  # replaced by raw value
            ],
            exclude_obj_callback=exclude_obj_callback,
        )
        assert diff == {}
    with open(binary_envelope, "rb") as fh_suit_1, open(binary_envelope_copy, "rb") as fh_suit_2:
        # restored yaml might be a little different due to replacements like RFC4122_UUID calculation -> raw data
        # but both envelopes should be binary equal
        assert calculate_hash(fh_suit_1.read()) == calculate_hash(fh_suit_2.read())


def test_envelope_unsigned_creation_and_parsing_multilevel_hierarchy(setup_and_teardown):
    """Test recreation of multilevel hierarchy envelope with hierarchy parsing enabled."""
    envelope = SuitEnvelope()
    # create multilevel hierarchy binary envelope
    envelope.load("envelope_3.yaml", input_type="yaml")
    envelope.dump("envelope_3.suit", output_type="suit")
    # load multilevel hierarchy binary envelope
    envelope.load("envelope_3.suit", input_type="suit")
    # dump envelope with dependent manifests parsed to yaml file
    envelope.dump("envelope_3_copy.yaml", output_type="yaml", parse_hierarchy=True)
    # recreate multilevel hierarchy binary envelope
    envelope.load("envelope_3_copy.yaml", input_type="yaml")
    envelope.dump("envelope_3_copy.suit", output_type="suit")
    # compare both envelopes
    with open("envelope_3.suit", "rb") as fh_suit_1, open("envelope_3_copy.suit", "rb") as fh_suit_2:
        # restored yaml might be a little different due to replacements like RFC4122_UUID calculation -> raw data
        # but both envelopes should be binary equal
        assert calculate_hash(fh_suit_1.read()) == calculate_hash(fh_suit_2.read())


@pytest.mark.parametrize("input_data", ["input_envelope_1"])
def test_envelope_parsing(setup_and_teardown, input_data):
    """Check if is possible to parse binary hierarchical envelope."""
    envelope = SuitEnvelope()
    envelope.load(f"{input_data}.suit", input_type="suit")
    assert type(envelope._envelope) is dict
    assert suit_integrated_dependencies.name in envelope._envelope["SUIT_Envelope_Tagged"]
    assert type(envelope._envelope["SUIT_Envelope_Tagged"][suit_integrated_dependencies.name]) is dict
    assert len(envelope._envelope["SUIT_Envelope_Tagged"][suit_integrated_dependencies.name]) == 2
