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

from suit_generator import (
    cmd_parse,
    cmd_keys,
    cmd_convert,
    cmd_create,
    cmd_image,
    cmd_mpi,
    cmd_cache_create,
    cmd_payload_extract,
    args,
)
from suit_generator.exceptions import GeneratorError, SUITError

import logging
import logging.config
import yaml

from pathlib import Path

logger = logging.getLogger(__name__)

COMMAND_EXECUTORS = {
    cmd_parse.PARSE_CMD: cmd_parse.main,
    cmd_create.CREATE_CMD: cmd_create.main,
    cmd_keys.KEYS_CMD: cmd_keys.main,
    cmd_convert.CONVERT_CMD: cmd_convert.main,
    cmd_image.ImageCreator.IMAGE_CMD: cmd_image.main,
    cmd_mpi.MPI_CMD: cmd_mpi.main,
    cmd_cache_create.CACHE_CREATE_CMD: cmd_cache_create.main,
    cmd_payload_extract.PAYLOAD_EXTRACT_CMD: cmd_payload_extract.main,
}


def configure_cli_logging(log_file_name: str = None):
    """
    Configure logging for CLI.

    :param log_file_name: log file name to be used (override default log file name from logging.yaml)
    """
    dir_path = Path(__file__).resolve().parent

    with open(dir_path / "logging.yaml", "r") as stream:
        config = yaml.load(stream, Loader=yaml.FullLoader)

    # override log file name if passed as argument
    if log_file_name:
        config["handlers"]["file"]["filename"] = log_file_name

    logging.config.dictConfig(config)

    # any logger initialized before call to 'configure_logging' will be disabled because logging.yaml
    # contains entry 'disable_existing_loggers: true', if yaml has no explicit configuration for it
    # so we need to defer logger creation (call to 'getLogger') after 'configure_logging' call or enable it manually
    logger.disabled = False
    logger.debug("*** suit-generator initialized and logging configuration loaded")


def main() -> None:
    """Parse input arguments and call passed CMD executor."""
    command, arguments, log_file = args.parse_arguments()

    configure_cli_logging(log_file)

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
