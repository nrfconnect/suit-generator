#
# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Unit tests for cmd_payload_extract.py implementation."""

import cbor2
import pytest

from suit_generator.cmd_payload_extract import payload_extract_recursive
from suit_generator.exceptions import GeneratorError

MANIFEST = b"manifest"


def envelope_with_payload(name, content):
    """Create a minimal envelope with a single integrated payload."""
    return cbor2.CBORTag(107, {3: MANIFEST, name: content})


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Run the test inside an empty directory that has a sibling directory with a file."""
    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "target.txt").write_bytes(b"original")
    monkeypatch.chdir(work)
    return work


def test_payload_extract_recursive_plain_name(workdir):
    """A payload with a plain file name is extracted into the current directory."""
    envelope = payload_extract_recursive(envelope_with_payload("payload.bin", b"content"), None, None)

    assert (workdir / "payload.bin").read_bytes() == b"content"
    assert "payload.bin" not in envelope.value


def test_payload_extract_recursive_subdirectory(workdir):
    """A payload name pointing into an existing subdirectory is extracted there."""
    (workdir / "sub").mkdir()
    payload_extract_recursive(envelope_with_payload("sub/payload.bin", b"content"), None, None)

    assert (workdir / "sub" / "payload.bin").read_bytes() == b"content"


def test_payload_extract_recursive_prefix_removed(workdir):
    """The prefix is removed from the payload name before the file is written."""
    payload_extract_recursive(envelope_with_payload("file://payload.bin", b"content"), None, None, "file://")

    assert (workdir / "payload.bin").read_bytes() == b"content"


def test_payload_extract_recursive_relative_path_outside(workdir):
    """A payload name leaving the current directory with '..' is rejected and nothing is written."""
    with pytest.raises(GeneratorError):
        payload_extract_recursive(envelope_with_payload("../outside/target.txt", b"content"), None, None)

    assert (workdir.parent / "outside" / "target.txt").read_bytes() == b"original"


def test_payload_extract_recursive_absolute_path_outside(workdir):
    """An absolute payload name outside of the current directory is rejected and nothing is written."""
    target = workdir.parent / "outside" / "target.txt"
    with pytest.raises(GeneratorError):
        payload_extract_recursive(envelope_with_payload(str(target), b"content"), None, None)

    assert target.read_bytes() == b"original"


def test_payload_extract_recursive_dependency_path_outside(workdir):
    """A payload of a dependency envelope pointing outside of the current directory is rejected."""
    dependency = cbor2.dumps(envelope_with_payload("../outside/target.txt", b"content"))
    with pytest.raises(GeneratorError):
        payload_extract_recursive(envelope_with_payload("dep.suit", dependency), None, r".*\.suit")

    assert (workdir.parent / "outside" / "target.txt").read_bytes() == b"original"
