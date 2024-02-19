#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Logger helper methods."""
import functools
import inspect

import logging

logger = logging.getLogger(__name__)


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
