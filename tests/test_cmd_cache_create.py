#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for cmd_cache_create.py implementation."""

import pytest
import pathlib
import os
from suit_generator.cmd_cache_create import main as cmd_cache_create_main

TEMP_DIRECTORY = pathlib.Path("test_test_data")

BINARY_CONTENT_1 = bytes([0x01, 0x02, 0x03, 0x04])
BINARY_CONTENT_2 = bytes([0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11])

URI1 = "#first"  # [0x23, 0x66, 0x69, 0x72, 0x73, 0x74]
URI2 = "#second"  # [0x23, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64]

EXPECTED_CACHE_EB_8 = bytes(
    [
        0xBF,
        0x66,
        0x23,
        0x66,
        0x69,
        0x72,
        0x73,
        0x74,  # tstr "first"
        0x5A,
        0x00,
        0x00,
        0x00,
        0x04,  # bstr size 4
        0x01,
        0x02,
        0x03,
        0x04,  # BINARY_CONTENT_1
        0x60,
        0x45,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,  # padding
        0x67,
        0x23,
        0x73,
        0x65,
        0x63,
        0x6F,
        0x6E,
        0x64,  # tstr "second"
        0x5A,
        0x00,
        0x00,
        0x00,
        0x0A,  # bstr size 10
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,  # BINARY_CONTENT_2
        0x60,
        0x47,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,  # padding
        0xFF,
    ]
)

EXPECTED_CACHE_EB_64 = bytes(
    [
        0xBF,
        0x66,
        0x23,
        0x66,
        0x69,
        0x72,
        0x73,
        0x74,  # tstr "first"
        0x5A,
        0x00,
        0x00,
        0x00,
        0x04,  # bstr size 4
        0x01,
        0x02,
        0x03,
        0x04,  # BINARY_CONTENT_1
        0x60,
        0x59,
        0x00,
        0x2B,  # padding 47 bytes (4 bytes header + 43 bytes padding)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x67,
        0x23,
        0x73,
        0x65,
        0x63,
        0x6F,
        0x6E,
        0x64,  # tstr "second"
        0x5A,
        0x00,
        0x00,
        0x00,
        0x0A,  # bstr size 10
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,  # BINARY_CONTENT_2
        0x60,
        0x59,
        0x00,
        0x25,  # padding 41 bytes (4 bytes header + 37 bytes padding)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xFF,
    ]
)


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
def test_cache_create(setup_and_teardown, eb_size, output_content):
    """Verify if is possible to create binary envelope from json input."""

    cmd_cache_create_main(
        input=[f"{URI1},first.bin", f"{URI2},second.bin"], output_file="test_cache.bin", eb_size=eb_size
    )

    with open("test_cache.bin", "rb") as f:
        assert f.read() == output_content
