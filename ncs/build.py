#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Implementation of build template engine to link the NCS build system with the suit-generator."""

import os
import sys
import pickle

from jinja2 import Template
from argparse import ArgumentParser


def convert(edt_object):
    """Convert devicetree representation into simplified object."""
    # TODO: returned data shall contain basic and the most important settings to simplify templates
    data = edt_object.label2node
    data["compat2vendor"] = edt_object.compat2vendor
    return data


def read_configurations(configurations):
    """Read configuration stored in the pickled devicetree."""
    data = {}
    for config in configurations:
        name, binary, edt = config.split(":")
        with open(edt, "rb") as edt_handler:
            edt = pickle.load(edt_handler)
            data[name] = {"name": name, "config": convert(edt), "dt": edt, "binary": binary}
    data["get_absolute_address"] = get_absolute_address
    return data


def render_template(template_location, data):
    """Render template using passed data."""
    with open(template_location) as template_file:
        template = Template(template_file.read())
    return template.render(data)


def get_absolute_address(node):
    """Get absolute address of passed node."""
    # fixme: hardcoded value for parent node due to bug in DTS
    # return node.parent.parent.regs[0].addr + node.regs[0].addr
    return 0xE000000 + node.regs[0].addr


parser = ArgumentParser()
parser.add_argument(
    "--core", action="append", required=True, help="Configuration of sample name:location of binaries:location of edt"
)
parser.add_argument("--version", required=True, default=1, help="Update version.")
parser.add_argument("--template-suit", required=True, help="Input SUIT jinja2 template.")
parser.add_argument("--output-suit", required=True, help="Output SUIT configuration.")
parser.add_argument("--template-settings", required=True, help="Input settings jinja2 template.")
parser.add_argument("--output-settings", required=True, help="Output settings.")
parser.add_argument("--output-envelope", required=True, help="Location of output envelope.")
parser.add_argument("--zephyr-base", required=True, help="Location of zephyr directory.")
arguments = parser.parse_args()

sys.path.insert(0, os.path.join(arguments.zephyr_base, "scripts", "dts", "python-devicetree", "src"))

configuration = read_configurations(arguments.core)
configuration["output_envelope"] = arguments.output_envelope
configuration["version"] = arguments.version
output_suit_content = render_template(arguments.template_suit, configuration)
# fixme: output settings should contain FW address extracted from devicetree, currently default address is being used.
output_settings_content = render_template(arguments.template_settings, configuration)

with open(arguments.output_suit, "w") as output_file:
    output_file.write(output_suit_content)

with open(arguments.output_settings, "w") as output_file:
    output_file.write(output_settings_content)
