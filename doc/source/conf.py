#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Configuration file for the Sphinx documentation builder."""

import datetime
import build.util
from importlib.metadata import version as get_version
from pathlib import Path

setup_cfg_path = Path(__file__).parents[2] / "setup.cfg"
conf_dict = build.util.project_wheel_metadata(setup_cfg_path.parent)

project = "suit_generator"
copyright = f"{datetime.datetime.now().year} Nordic Semiconductor ASA"
author = conf_dict["Author"]
version = get_version(conf_dict["Name"])

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.ifconfig",
    "sphinx.ext.viewcode",
    "sphinx.ext.githubpages",
    "sphinx.ext.autosectionlabel",
    "sphinxarg.ext",
]

# default role assumed when using backticks
default_role = "any"
# order by source
autodoc_member_order = "bysource"
always_document_param_types = True
# create documentation using only class` docstring (__init__ will be skipped)
autoclass_content = "class"
html_theme = "sphinx_ncs_theme"
