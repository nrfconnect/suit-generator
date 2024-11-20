#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for cmd_cache_create.py implementation."""

import pytest
import pathlib
import os
import cbor2
from suit_generator.cmd_cache_create import main as cmd_cache_create_main
from suit_generator.cmd_create import main as cmd_create_main

TEMP_DIRECTORY = pathlib.Path("test_test_data")

BINARY_CONTENT_1 = bytes([0x01, 0x02, 0x03, 0x04])
BINARY_CONTENT_2 = bytes([0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11])
BINARY_CONTENT_3 = bytes(
    [
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
    ]
)

URI1 = "#first"  # [0x23, 0x66, 0x69, 0x72, 0x73, 0x74]
URI2 = "#second"  # [0x23, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64]
URI3 = "#third"  # [0x23, 0x74, 0x68, 0x69, 0x72, 0x64]
ENVELOPE_ROOT_YAML = """SUIT_Envelope_Tagged:
  suit-authentication-wrapper:
    SuitDigest:
      suit-digest-algorithm-id: cose-alg-sha-256
      suit-digest-bytes: 60198229d4c07c866094a3d19c2d8b15b5dd552cd5bba5cf8f78e492ccbb3327
  suit-manifest:
    suit-manifest-component-id:
    - raw: aa
  suit-integrated-dependencies:
      'dependency_manifest': dep.suit
      '#first': first.bin
"""

ENVELOPE_DEP_YAML = """SUIT_Envelope_Tagged:
  suit-authentication-wrapper:
    SuitDigest:
      suit-digest-algorithm-id: cose-alg-sha-256
      suit-digest-bytes: b2afeba5d8172371661b7ab5d7242c2ba6797ae27e713114619d90663ab6a2ec
  suit-manifest:
    suit-manifest-component-id:
    - raw: bb
  suit-integrated-dependencies:
      '#second': second.bin
      '#third': third.bin
"""

# fmt: off
EXPECTED_CACHE_EB_8 = bytes([0xBF,
                             0x66, 0x23, 0x66, 0x69, 0x72, 0x73, 0x74,  # tstr "#first"
                             0x5A, 0x00, 0x00, 0x00, 0x04,  # bstr size 4
                             0x01, 0x02, 0x03, 0x04,  # BINARY_CONTENT_1
                             0x60, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00,  # padding
                             0x67, 0x23, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64,  # tstr "#second"
                             0x5A, 0x00, 0x00, 0x00, 0x0a,  # bstr size 10
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,  # BINARY_CONTENT_2
                             0x60, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # padding
                             0xFF])

EXPECTED_CACHE_EB_64 = bytes([0xBF,
                             0x66, 0x23, 0x66, 0x69, 0x72, 0x73, 0x74,  # tstr "#first"
                             0x5A, 0x00, 0x00, 0x00, 0x04,  # bstr size 4
                             0x01, 0x02, 0x03, 0x04,  # BINARY_CONTENT_1
                             0x60, 0x59, 0x00, 0x2B,  # padding 47 bytes (4 bytes header + 43 bytes padding)
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00,
                             0x67, 0x23, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64,  # tstr "#second"
                             0x5A, 0x00, 0x00, 0x00, 0x0a,  # bstr size 10
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,  # BINARY_CONTENT_2
                             0x60, 0x59, 0x00, 0x25,  # padding 41 bytes (4 bytes header + 37 bytes padding)
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00,
                             0xFF])
# fmt: on


@pytest.fixture
def setup_and_teardown(tmp_path_factory):
    """Create and cleanup environment."""
    # Setup environment
    #   - create temp directory
    #   - input files
    start_directory = os.getcwd()
    path = tmp_path_factory.mktemp(TEMP_DIRECTORY)
    os.chdir(path)
    with open("first.bin", "wb") as fh:
        fh.write(BINARY_CONTENT_1)
    with open("second.bin", "wb") as fh:
        fh.write(BINARY_CONTENT_2)
    with open("third.bin", "wb") as fh:
        fh.write(BINARY_CONTENT_3)
    yield
    # Cleanup environment
    #   - remove temp directory
    os.chdir(start_directory)


@pytest.mark.parametrize(
    "eb_size, output_content",
    [
        (8, EXPECTED_CACHE_EB_8),
        (64, EXPECTED_CACHE_EB_64),
    ],
)
def test_cache_create_from_payloads(setup_and_teardown, eb_size, output_content):
    """Verify if the cache is correctly created from payloads."""

    cmd_cache_create_main(
        cache_create_subcommand="from_payloads",
        input=[f"{URI1},first.bin", f"{URI2},second.bin"],
        output_file="test_cache.bin",
        eb_size=eb_size,
    )

    with open("test_cache.bin", "rb") as f:
        assert f.read() == output_content


def test_cache_create_merge(setup_and_teardown):
    """Verify if the cache is correctly created from two other cache partitions."""

    cmd_cache_create_main(
        cache_create_subcommand="from_payloads",
        input=[f"{URI1},first.bin", f"{URI2},second.bin"],
        output_file="test_cache1.bin",
        eb_size=8,
    )
    cmd_cache_create_main(
        cache_create_subcommand="from_payloads", input=[f"{URI3},third.bin"], output_file="test_cache2.bin", eb_size=4
    )

    cmd_cache_create_main(
        cache_create_subcommand="from_payloads",
        input=[f"{URI1},first.bin", f"{URI2},second.bin", f"{URI3},third.bin"],
        output_file="test_cache_merged_expected.bin",
        eb_size=16,
    )

    cmd_cache_create_main(
        cache_create_subcommand="merge",
        input=["test_cache1.bin", "test_cache2.bin"],
        output_file="test_cache_merged.bin",
        eb_size=16,
    )

    with open("test_cache_merged.bin", "rb") as f:
        result = f.read()

    with open("test_cache_merged_expected.bin", "rb") as f:
        expected = f.read()

    # Assert that cache resulting from merging two caches is the same as if the cache was created from the payloads
    assert result == expected


def test_cache_create_merge_from_envelope(setup_and_teardown):
    # Prepare envelope files
    with open("root.yaml", "w") as fh:
        fh.write(ENVELOPE_ROOT_YAML)
    with open("dep.yaml", "w") as fh:
        fh.write(ENVELOPE_DEP_YAML)
    cmd_create_main(input_file="dep.yaml", output_file="dep.suit", input_format="AUTO")
    cmd_create_main(input_file="root.yaml", output_file="root.suit", input_format="AUTO")

    cmd_cache_create_main(
        cache_create_subcommand="from_envelope",
        input_envelope="root.suit",
        output_envelope="root_stripped.suit",
        output_file="test_cache_from_envelope.bin",
        eb_size=8,
        omit_payload_regex=".*third",
        dependency_regex="dep.*",
    )

    with open("test_cache_from_envelope.bin", "rb") as f:
        assert f.read() == EXPECTED_CACHE_EB_8

    with open("root_stripped.suit", "rb") as fh:
        envelope_stripped = cbor2.load(fh)

    assert "#first" not in envelope_stripped.value.keys()

    dependency = envelope_stripped.value.pop("dependency_manifest", None)
    assert dependency is not None
    dependency = cbor2.loads(dependency).value

    assert "#second" not in dependency.keys()

    not_extracted = dependency.pop("#third", None)
    assert not_extracted is not None
    assert not_extracted == BINARY_CONTENT_3
