#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Main script for setuptools."""

import setuptools

# Required for installing a project in editable mode (i.e. setuptools "develop mode")
setuptools.setup(use_scm_version=True, setup_requires=["setuptools_scm"])
