#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Main CLI entry point."""

from suit_generator import cmd_parse, cmd_sign, cmd_keys, cmd_convert, cmd_create, cmd_image, args
from suit_generator.exceptions import GeneratorError, SUITError

import logging
import sys

FORMAT = "%(asctime)s:%(levelname)s:%(message)s"
logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format=FORMAT)

COMMAND_EXECUTORS = {
    args.PARSE_CMD: cmd_parse.main,
    args.CREATE_CMD: cmd_create.main,
    args.KEYS_CMD: cmd_keys.main,
    args.CONVERT_CMD: cmd_convert.main,
    args.SIGN_CMD: cmd_sign.main,
    args.IMAGE_CMD: cmd_image.main,
}


def main() -> int:
    """Parse input arguments and call passed CMD executor."""
    command, arguments = args.parse_arguments()
    # passing arguments as kwargs used to simplify commands calling, improve documentation and error handling
    try:
        COMMAND_EXECUTORS[command](**vars(arguments))
    except GeneratorError as error:
        print(f"Error: {error}")
        return 1
    except SUITError as error:
        print(f"SUIT error: {error}")
        return 2
    else:
        return 0


if __name__ == "__main__":
    main()
