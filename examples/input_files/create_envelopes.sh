#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
#!/usr/bin/env sh
# Create two basic envelopes containing dummy payloads.
dd if=/dev/zero of=file.bin bs=1024 count=1
suit-generator create --input-file envelope_1.json --output-file test_envelope_from_json.suit
suit-generator create --input-file envelope_1.yaml --output-file test_envelope_from_yaml.suit

