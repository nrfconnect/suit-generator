#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""CMD_PAYLOAD_EXTRACT CLI command entry point."""

import cbor2
import logging
import re
from suit_generator.exceptions import GeneratorError

log = logging.getLogger(__name__)

PAYLOAD_EXTRACT_CMD = "payload_extract"

PAYLOAD_EXTRACT_SINGLE_CMD = "single"
PAYLOAD_EXTRACT_RECURSIVE_CMD = "recursive"


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_payload_extract_arg_parser = parser.add_parser(PAYLOAD_EXTRACT_CMD, help="Create raw cache structure.")

    cmd_payload_extract_subparsers = cmd_payload_extract_arg_parser.add_subparsers(
        dest="payload_extract_subcommand", required=True, help="Choose sign subcommand"
    )

    cmd_payload_extract_single = cmd_payload_extract_subparsers.add_parser(
        PAYLOAD_EXTRACT_SINGLE_CMD,
        help="Extact a single payload from a SUIT envelope.",
    )

    cmd_payload_extract_single.add_argument("--input-envelope", required=True, help="Input envelope file path.")
    cmd_payload_extract_single.add_argument("--output-envelope", required=True, help="Output envelope file path.")
    cmd_payload_extract_single.add_argument(
        "--payload-name", required=True, help="Name of the integrated payload to extract."
    )
    cmd_payload_extract_single.add_argument(
        "--output-payload-file",
        required=False,
        help="Output payload file path to store the extracted payload."
        + "If not provided, the payload will not be stored to a file.",
    )

    cmd_payload_extract_single.add_argument(
        "--payload-replace-path",
        help="Path to the integrated payload to replace the extracted payload with. "
        + "If not provided, the payload will be removed from the envelope.",
    )

    cmd_payload_extract_recursive = cmd_payload_extract_subparsers.add_parser(
        PAYLOAD_EXTRACT_RECURSIVE_CMD,
        help="Recursively extract payloads from a SUIT envelope based on regular expressions. "
        + "The resulting file names will be the based on the payload names.",
    )
    cmd_payload_extract_recursive.add_argument("--input-envelope", required=True, help="Input envelope file path.")

    cmd_payload_extract_recursive.add_argument(
        "--output-envelope", required=True, help="Output envelope file path (envelope with removed extracted payloads)."
    )

    cmd_payload_extract_recursive.add_argument(
        "--omit-payload-regex",
        help="Integrated payloads matching the regular expression will not be extracted into files.",
    )

    cmd_payload_extract_recursive.add_argument(
        "--dependency-regex",
        help="Integrated payloads matching the regular expression will be treated as dependency"
        + "envelopes and parsed hierarchically. "
        + "The payloads extracted from the dependency envelopes will be extracted into files.",
    )

    cmd_payload_extract_recursive.add_argument(
        "--payload-file-prefix-to-remove",
        help="Prefix to remove from the extracted payload file names. "
        + "For example, if the payload is named file://my_file.bin, the prefix file:// will be removed if "
        + "this argument is set to 'file://'.",
    )


def payload_extract_single(
    envelope: cbor2.CBORTag, payload_name: str, output_payload_file: str, payload_replace_path: str
) -> cbor2.CBORTag:
    """Extract a single integrated payload from a SUIT envelope.

    :param input_envelope: input envelope file path
    :param output_envelope: output envelope file path
    :param payload_name: name of the integrated payload to extract
    :param output_payload_file: output file path to store the extracted payload
        None if the payload should not be stored to a file
    :param payload_replace_path: Path to the integrated payload to replace the extracted payload with.
        None if the payload should be removed from the envelope.
    :return envelope with removed extracted payload
    """
    extracted_payload = envelope.value.pop(payload_name, None)

    if extracted_payload is None:
        log.log(logging.ERROR, 'Payload "%s" not found in envelope', payload_name)

    if payload_replace_path is not None:
        with open(payload_replace_path, "rb") as fh:
            envelope.value[payload_name] = fh.read()

    if output_payload_file is not None:
        with open(output_payload_file, "wb") as fh:
            fh.write(extracted_payload)

    return envelope


def payload_extract_recursive(
    envelope: cbor2.CBORTag, omit_payload_regex: str, dependency_regex: str, payload_file_prefix_to_remove: str = None
) -> cbor2.CBORTag:
    """Recursively extract payloads from a SUIT envelope based on regular expressions.

    :param input_envelope: input envelope file path
    :param output_envelope: output envelope file path
    :param omit_payload_regex: integrated payloads matching the regular expression will not be extracted into files
    :param dependency_regex: integrated payloads matching the regular expression will be treated as dependency
           envelopes and parsed hierarchically. The payloads extracted from the dependency envelopes will be extracted
           into files.
    :return: envelope with removed extracted payloads
    """
    integrated = [k for k in envelope.value.keys() if isinstance(k, str)]

    if dependency_regex is not None:
        integrated_dependencies = [k for k in integrated if not re.fullmatch(dependency_regex, k) is None]
        for dep in integrated_dependencies:
            integrated.remove(dep)
    else:
        integrated_dependencies = []

    if omit_payload_regex is None:
        payloads_to_extract = integrated
    else:
        payloads_to_extract = [k for k in integrated if re.fullmatch(omit_payload_regex, k) is None]

    for payload in payloads_to_extract:
        payload_file_name = payload
        # Remove prefix from the payload file name
        if payload_file_prefix_to_remove is not None:
            if payload.startswith(payload_file_prefix_to_remove):
                payload_file_name = payload[len(payload_file_prefix_to_remove) :]
        with open(payload_file_name, "wb") as fh:
            fh.write(envelope.value.pop(payload))

    for dependency in integrated_dependencies:
        try:
            try:
                dependency_envelope = cbor2.loads(envelope.value[dependency])
            except Exception:
                raise GeneratorError("The dependency is not a valid envelope!")

            if not (isinstance(dependency_envelope, cbor2.CBORTag) and isinstance(dependency_envelope.value, dict)):
                raise GeneratorError("The dependency is not a valid envelope!")

            new_dependency_envelope = payload_extract_recursive(
                dependency_envelope, omit_payload_regex, dependency_regex, payload_file_prefix_to_remove
            )
        except GeneratorError as e:
            log.log(logging.ERROR, "Failed to extract payloads from dependency %s: %s", dependency, repr(e))
            raise GeneratorError("Failed to extract payloads from envelope!")

        envelope.value[dependency] = cbor2.dumps(new_dependency_envelope)

    return envelope


def main(**kwargs) -> None:
    """Extract a integrated payloads from a SUIT envelope."""
    with open(kwargs["input_envelope"], "rb") as fh:
        envelope = cbor2.load(fh)

    if kwargs["payload_extract_subcommand"] == PAYLOAD_EXTRACT_SINGLE_CMD:
        output_envelope = payload_extract_single(
            envelope,
            kwargs["payload_name"],
            kwargs["output_payload_file"],
            kwargs["payload_replace_path"],
        )
    elif kwargs["payload_extract_subcommand"] == PAYLOAD_EXTRACT_RECURSIVE_CMD:
        output_envelope = payload_extract_recursive(
            envelope,
            kwargs["omit_payload_regex"],
            kwargs["dependency_regex"],
            kwargs["payload_file_prefix_to_remove"],
        )
    else:
        raise GeneratorError(f"Invalid 'payload_extract' subcommand: {kwargs['payload_extract_subcommand']}")

    with open(kwargs["output_envelope"], "wb") as fh:
        cbor2.dump(output_envelope, fh)
