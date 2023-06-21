#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Script waiting for passed files appearance."""

import logging
import time
from argparse import ArgumentParser
from pathlib import Path

parser = ArgumentParser()
parser.add_argument("--file", action="append", required=True, help="File location to look for.")
parser.add_argument("--max-time", type=int, required=True, default=60, help="Maximum waiting time for file appearance.")
arguments = parser.parse_args()

logging.basicConfig(level=logging.DEBUG)
logging.info(f"waiting for {arguments.file} with timeout {arguments.max_time}")

start_time = time.time()
while True:
    for file in arguments.file:
        if Path(file).is_file():
            arguments.file.remove(file)
        if len(arguments.file) == 0:
            exit()
        if time.time() - start_time > arguments.max_time:
            logging.error("not all required files available")
            exit(1)
        logging.info(f"waiting ({int(time.time() - start_time)})...")
        time.sleep(1)
