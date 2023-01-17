"""Main script for setuptools."""
##########################################################################################
# Copyright (c) 2015 - 2022 Nordic Semiconductor ASA. All Rights Reserved.
#
# The information contained herein is confidential property of Nordic Semiconductor ASA.
# The use, copying, transfer or disclosure of such information is prohibited except by
# express written agreement with Nordic Semiconductor ASA.
##########################################################################################

import setuptools

# Required for installing a project in editable mode (i.e. setuptools "develop mode")
setuptools.setup(use_scm_version=True, setup_requires=["setuptools_scm"])
