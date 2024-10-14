#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""CMD_PAYLOAD_EXTRACT CLI command entry point."""

import cbor2
import logging

log = logging.getLogger(__name__)

PAYLOAD_EXTRACT_CMD = "payload_extract"


def add_arguments(parser):
    """Add additional arguments to the passed parser."""
    cmd_payload_extract_arg_parser = parser.add_parser(PAYLOAD_EXTRACT_CMD, help="Create raw cache structure.")

    cmd_payload_extract_arg_parser.add_argument("--input-envelope", required=True, help="Input envelope file path.")
    cmd_payload_extract_arg_parser.add_argument("--output-envelope", required=True, help="Output envelope file path.")
    cmd_payload_extract_arg_parser.add_argument(
        "--payload-name", required=True, help="Name of the integrated payload to extract."
    )
    cmd_payload_extract_arg_parser.add_argument(
        "--output-payload-file",
        required=False,
        help="Output payload file path to store the extracted payload."
        + "If not provided, the payload will not be stored to a file.",
    )

    cmd_payload_extract_arg_parser.add_argument(
        "--payload-replace-path",
        help="Path to the integrated payload to replace the extracted payload with."
        + "If not provided, the payload will be removed from the envelope.",
    )


def main(
    input_envelope: str, output_envelope: str, payload_name: str, output_payload_file: str, payload_replace_path: str
) -> None:
    """Extract an integrated payload from a SUIT envelope.

    :param input_envelope: input envelope file path
    :param output_envelope: output envelope file path
    :param payload_name: name of the integrated payload to extract
    :param output_payload_file: output file path to store the extracted payload
        None if the payload should not be stored to a file
    :param payload_replace_path: Path to the integrated payload to replace the extracted payload with.
        None if the payload should be removed from the envelope.
    """
    with open(input_envelope, "rb") as fh:
        envelope = cbor2.load(fh)
    extracted_payload = envelope.value.pop(payload_name, None)

    if extracted_payload is None:
        log.log(logging.ERROR, 'Payload "%s" not found in envelope', payload_name)

    if payload_replace_path is not None:
        with open(payload_replace_path, "rb") as fh:
            envelope.value[payload_name] = fh.read()

    with open(output_envelope, "wb") as fh:
        cbor2.dump(envelope, fh)
    if output_payload_file is not None:
        with open(output_payload_file, "wb") as fh:
            fh.write(extracted_payload)
