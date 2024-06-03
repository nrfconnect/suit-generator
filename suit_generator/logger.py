#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Logger helper methods."""
from __future__ import annotations

import functools
import inspect

import logging
import logging.config

from typing import Any
from pathlib import Path


logger = logging.getLogger(__name__)

DEFAULT_LOG_FORMAT: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DEFAULT_LOG_FILE_PATH: Path = 'suit-generator.log'


def log_call(func):
    """Decorate function or method if call shall be logged."""

    @functools.wraps(func)
    def inner_func(*args, **kwargs):
        try:
            caller_frame_record = inspect.stack()[1]
            frame = caller_frame_record[0]
            info = inspect.getframeinfo(frame)
            logger.debug(f"{info.filename}:{info.function}:{info.lineno}:{func.__name__}({args=},{kwargs=})")
            return func(*args, **kwargs)
        except Exception as e:
            logger.warning(f"{info.filename}:{info.function}:{info.lineno}:{func.__name__}({args=},{kwargs=}):\n{e}")
            raise

    return inner_func


def get_default_logger_config() -> dict[str, Any]:
    """
    Get default logger configuration.
    Use variables DEFAULT_LOG_FORMAT and DEFAULT_LOG_FILE_PATH to override log format and log file path.

    :return: Default logger configuration dictionary
    """
    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'simple': {
                'format': DEFAULT_LOG_FORMAT,
            },
        },
        'handlers': {
            'file': {
                'class': 'logging.handlers.RotatingFileHandler',
                'formatter': 'simple',
                'level': 'DEBUG',
                'filename': DEFAULT_LOG_FILE_PATH,
                'mode': 'a',
                'backupCount': 10,  # max 10 files
                'maxBytes': 10485760  # max ten mega bytes (1024*1024*10)
            },
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'ERROR',
                'formatter': 'simple',
                'stream': 'ext://sys.stdout',
            }
        },
        'loggers': {
            'suit_generator': {
                'level': 'DEBUG',
                'handlers': ['file', 'console'],
                'propagate': False,
            },
            'suit_generator.suit.types.common': {
                'level': 'DEBUG',
                'handlers': ['file'],
                'propagate': False,
            },
            'suit_generator.logger': {
                'level': 'DEBUG',
                'handlers': ['file'],
                'propagate': False,
            },
            'ncs': {
                'level': 'DEBUG',
                'handlers': ['file'],
                'propagate': False,
            },
        }
    }

    return config


def configure_logging(config: dict[str, Any] | None = None) -> None:
    """
    Function configures logging. If no configuration is passed, default configuration is used.

    :param config: Logging configuration
    """
    if config is None:
        config = get_default_logger_config()

    logging.config.dictConfig(config)

    logger.debug("*** suit-generator initialized and logging configuration loaded")
