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
            logger.debug(f"Unable to parse data: {args=},{kwargs=}")
            raise

    return inner_func
