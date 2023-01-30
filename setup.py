#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
"""Main script for setuptools."""

import setuptools

# Required for installing a project in editable mode (i.e. setuptools "develop mode")
setuptools.setup(use_scm_version=True, setup_requires=["setuptools_scm"])
