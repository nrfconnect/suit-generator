#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#

"""Custom exceptions specific to SUIT Generator."""


class GeneratorError(Exception):
    """Indicates errors related to the tool (e.g. invalid commandline parameters combination)."""


class SUITError(Exception):
    """Indicates errors related to SUIT (e.g. malformed envelope structure)."""
