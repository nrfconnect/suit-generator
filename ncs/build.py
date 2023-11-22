#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
"""Implementation of build template engine to link the NCS build system with the suit-generator."""

import os
import sys
import pickle
import pathlib
import re

from jinja2 import Template
from argparse import ArgumentParser

sys.path.insert(0, str(pathlib.Path(__file__).parents[1].absolute()))

from suit_generator.cmd_image import ImageCreator  # noqa: E402

TEMPLATE_CMD = "template"
STORAGE_CMD = "storage"


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
        name, binary, edt = config.split(",")
        with open(edt, "rb") as edt_handler:
            edt = pickle.load(edt_handler)
            # add prefix _ to the names starting with digits, for example:
            #   802154_rpmsg_subimage will be available in the templates as _802154_rpmsg_subimage
            data[f"_{name}" if re.match("^[0-9].*]", name) else name] = {
                "name": name,
                "config": convert(edt),
                "dt": edt,
                "binary": binary,
            }
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


parent_parser = ArgumentParser(add_help=False)
parent_parser.add_argument(
    "--core", action="append", required=True, help="Configuration of sample name:location of binaries:location of edt"
)
parent_parser.add_argument("--zephyr-base", required=True, help="Location of zephyr directory.")

parser = ArgumentParser(add_help=False)

subparsers = parser.add_subparsers(dest="command", required=True, help="Choose subcommand:")
cmd_template_arg_parser = subparsers.add_parser(
    TEMPLATE_CMD, help="Generate SUIT configuration files based on input templates.", parents=[parent_parser]
)
cmd_storage_arg_parser = subparsers.add_parser(
    STORAGE_CMD, help="Generate SUIT storage required by scecure domain.", parents=[parent_parser]
)

cmd_template_arg_parser.add_argument("--version", required=True, default=1, help="Update version.")
cmd_template_arg_parser.add_argument("--template-suit", required=True, help="Input SUIT jinja2 template.")
cmd_template_arg_parser.add_argument("--output-suit", required=True, help="Output SUIT configuration.")

cmd_storage_arg_parser.add_argument(
    "--input-envelope", required=True, action="append", help="Location of input envelope(s)."
)
cmd_storage_arg_parser.add_argument("--storage-output-file", required=True, help="Input binary SUIT envelope.")

arguments = parser.parse_args()

sys.path.insert(0, os.path.join(arguments.zephyr_base, "scripts", "dts", "python-devicetree", "src"))

configuration = read_configurations(arguments.core)

if arguments.command == TEMPLATE_CMD:
    configuration["version"] = arguments.version
    configuration["output_envelope"] = arguments.output_suit
    output_suit_content = render_template(arguments.template_suit, configuration)
    with open(arguments.output_suit, "w") as output_file:
        output_file.write(output_suit_content)

elif arguments.command == STORAGE_CMD:
    # fixme: envelope_address, update_candidate_info_address and dfu_max_caches shall be extracted from DTS
    ImageCreator.create_files_for_boot(
        input_files=arguments.input_envelope,
        storage_output_file=arguments.storage_output_file,
        envelope_address=ImageCreator.default_envelope_address,
        envelope_slot_size=ImageCreator.default_envelope_slot_size,
        update_candidate_info_address=ImageCreator.default_update_candidate_info_address,
        dfu_max_caches=ImageCreator.default_dfu_max_caches,
    )
