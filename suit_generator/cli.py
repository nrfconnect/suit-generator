#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Main CLI entry point."""
if __name__ == "__main__":
    # add paths if called as cli script
    import sys
    import pathlib

    sys.path.insert(0, str(pathlib.Path(__file__).parents[1].absolute()))

from suit_generator import cmd_parse, cmd_keys, cmd_convert, cmd_create, cmd_image, cmd_mpi, args
from suit_generator.exceptions import GeneratorError, SUITError

import logging

logger = logging.getLogger(__name__)

COMMAND_EXECUTORS = {
    cmd_parse.PARSE_CMD: cmd_parse.main,
    cmd_create.CREATE_CMD: cmd_create.main,
    cmd_keys.KEYS_CMD: cmd_keys.main,
    cmd_convert.CONVERT_CMD: cmd_convert.main,
    cmd_image.ImageCreator.IMAGE_CMD: cmd_image.main,
    cmd_mpi.MPI_CMD: cmd_mpi.main,
}


def main() -> None:
    """Parse input arguments and call passed CMD executor."""
    command, arguments = args.parse_arguments()
    # passing arguments as kwargs used to simplify commands calling, improve documentation and error handling
    try:
        COMMAND_EXECUTORS[command](**vars(arguments))
    except GeneratorError as error:
        # use error instead of exception to do not fold end user by too much information
        logger.error(error)
        exit(1)
    except SUITError as error:
        # use error instead of exception to do not fold end user by too much information
        logger.error(error)
        exit(1)


if __name__ == "__main__":
    main()
