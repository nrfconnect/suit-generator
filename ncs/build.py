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
import logging
import yaml

from jinja2 import Template
from argparse import ArgumentParser
from configparser import ConfigParser

sys.path.insert(0, str(pathlib.Path(__file__).parents[1].absolute()))

from suit_generator.cmd_image import ImageCreator  # noqa: E402
from build_configuration.configuration import BuildConfiguration  # noqa: E402

TEMPLATE_CMD = "template"
STORAGE_CMD = "storage"
UPDATE_CMD = "update"

dir_path = pathlib.Path(__file__).parent.absolute()


def read_configurations(configurations, target):
    """Read configuration stored in the pickled devicetree."""
    data = {}
    for config in configurations:
        args = config.split(",")
        if len(args) < 4:
            raise ValueError("Invalid number of input arguments")

        # Parse obligatory arguments
        name, binary, edt, kconfig = args[:4]

        edt_data = None
        if edt:
            with open(edt, "rb") as edt_handler:
                edt_data = pickle.load(edt_handler)
        # add prefix _ to the names starting with digits, for example:
        #   802154_rpmsg_subimage will be available in the templates as _802154_rpmsg_subimage
        image_name = f"_{name}" if re.match("^[0-9].*]", name) else name

        if image_name in data:
            existing_binary = data[image_name]["binary"]
            raise ValueError(
                f"Two images have the same CONFIG_SUIT_ENVELOPE_TARGET value for image {image_name}: {binary} and {existing_binary}"
            )

        data[image_name] = {
            "name": name,
            "config": BuildConfiguration(kconfig),
        }
        if edt_data:
            data[image_name]["dt"] = edt_data
        if binary:
            data[image_name]["filename"] = pathlib.Path(binary).name
            data[image_name]["binary"] = binary
        if target == image_name:
            data["target"] = data[image_name]
    data["get_absolute_address"] = get_absolute_address
    return data


def append_default_version_values(cfg):
    """Generate DEFAULT_SEQ_NUM and DEFAULT_VERSION variables."""
    extraversion_re = r"^(alpha|beta|rc)[\.]{0,1}([0-9]+){0,1}$"
    version = cfg["VERSION"]

    if "APP_ROOT_VERSION" in version:
        default_version = version["APP_ROOT_VERSION"]
    elif ("VERSION_MAJOR" in version) and ("VERSION_MINOR" in version) and ("PATCHLEVEL" in version):
        default_version = version["VERSION_MAJOR"] + "." + version["VERSION_MINOR"] + "." + version["PATCHLEVEL"]
        if "EXTRAVERSION" in version:
            extra = re.match(extraversion_re, version["EXTRAVERSION"])
            if extra is not None:
                default_version += "-" + ".".join([v for v in extra.groups() if v is not None])
            elif len(version["EXTRAVERSION"]) > 0:
                # Use the least important pre-release tag for unsupported values
                default_version += "-alpha"
    else:
        default_version = None

    if "APP_ROOT_SEQ_NUM" in version:
        default_seq_num = version["APP_ROOT_SEQ_NUM"]
    elif ("VERSION_MAJOR" in version) and ("VERSION_MINOR" in version) and ("PATCHLEVEL" in version):
        default_seq_num = (
            (int(version["VERSION_MAJOR"]) << 24)
            + (int(version["VERSION_MINOR"]) << 16)
            + (int(version["PATCHLEVEL"]) << 8)
        )
        if "VERSION_TWEAK" in version:
            default_seq_num += int(version["VERSION_TWEAK"])
    else:
        default_seq_num = 1

    if "DEFAULT_VERSION" not in version:
        if default_version is not None:
            cfg["VERSION"]["DEFAULT_VERSION"] = default_version
    if "DEFAULT_SEQ_NUM" not in version:
        cfg["VERSION"]["DEFAULT_SEQ_NUM"] = f"{default_seq_num}"

    # Handle SCFW versioning schema - it is customized by overwriting the Zephyr's version.cmake file.
    if (
        ("SYSCTRL_VERSION_MAJOR" in version)
        and ("SYSCTRL_VERSION_MINOR" in version)
        and ("SYSCTRL_VERSION_PATCH" in version)
    ):
        default_scfw_version = (
            version["SYSCTRL_VERSION_MAJOR"]
            + "."
            + version["SYSCTRL_VERSION_MINOR"]
            + "."
            + version["SYSCTRL_VERSION_PATCH"]
        )
        if "SYSCTRL_VERSION_EXTRA" in version:
            extra = re.match(extraversion_re, version["SYSCTRL_VERSION_EXTRA"])
            if extra is not None:
                default_scfw_version += "-" + ".".join([v for v in extra.groups() if v is not None])
            elif len(version["SYSCTRL_VERSION_EXTRA"]) > 0:
                # Use the least important pre-release tag for unsupported values
                default_scfw_version += "-alpha"

        default_scfw_seq_num = (
            (int(version["SYSCTRL_VERSION_MAJOR"]) << 24)
            + (int(version["SYSCTRL_VERSION_MINOR"]) << 16)
            + (int(version["SYSCTRL_VERSION_PATCH"]) << 8)
        )
        if "SYSCTRL_VERSION_TWEAK" in version:
            default_scfw_seq_num += int(version["SYSCTRL_VERSION_TWEAK"])
    else:
        default_scfw_version = None
        default_scfw_seq_num = 1

    if "SCFW_VERSION" not in version:
        if default_scfw_version is not None:
            cfg["VERSION"]["SCFW_VERSION"] = default_scfw_version
    if "SCFW_SEQ_NUM" not in version:
        cfg["VERSION"]["SCFW_SEQ_NUM"] = f"{default_scfw_seq_num}"


def read_version_file(version_file):
    """Read values from the VERSION configuration file."""
    with open(version_file, "r") as ver_values:
        cfg = ConfigParser()
        cfg.optionxform = lambda option: option
        cfg.read_string("[VERSION]\n" + ver_values.read())
        append_default_version_values(cfg)
        return cfg.items("VERSION")
    return {}


def render_template(template_location, data):
    """Render template using passed data."""
    with open(template_location) as template_file:
        template = Template(template_file.read())
    return template.render(data)


def get_absolute_address(node, use_offset: bool = True):
    """Get absolute address of passed node."""
    if use_offset:
        return node.parent.parent.regs[0].addr + node.regs[0].addr
    return node.regs[0].addr


if __name__ == "__main__":
    with open(dir_path.parent / "suit_generator" / "logging.yaml", "r") as stream:
        config = yaml.load(stream, Loader=yaml.FullLoader)

    logging.config.dictConfig(config)

    logger = logging.getLogger("ncs")
    logger.debug("ncs build script initialized and logging configuration loaded")

    parent_parser = ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--core",
        action="append",
        required=True,
        help="Configuration of sample name:location of binaries:location of edt",
    )
    parent_parser.add_argument("--zephyr-base", required=True, help="Location of zephyr directory.")
    parent_parser.add_argument("--target", required=False, default=None, help="Target name.")

    parser = ArgumentParser(add_help=False)

    subparsers = parser.add_subparsers(dest="command", required=True, help="Choose subcommand:")
    cmd_template_arg_parser = subparsers.add_parser(
        TEMPLATE_CMD, help="Generate SUIT configuration files based on input templates.", parents=[parent_parser]
    )
    cmd_storage_arg_parser = subparsers.add_parser(
        STORAGE_CMD, help="Generate SUIT storage required by secure domain.", parents=[parent_parser]
    )

    cmd_template_arg_parser.add_argument("--artifacts-folder", required=True, help="Output artifact folder.")
    cmd_template_arg_parser.add_argument("--template-suit", required=True, help="Input SUIT jinja2 template.")
    cmd_template_arg_parser.add_argument("--output-suit", required=True, help="Output SUIT file.")
    cmd_template_arg_parser.add_argument(
        "--version_file", required=False, default=None, help="Path to the VERSION file to use."
    )

    cmd_storage_arg_parser.add_argument(
        "--input-envelope", required=True, action="append", help="Location of input envelope(s)."
    )
    cmd_storage_arg_parser.add_argument(
        "--storage-output-directory", required=True, help="Directory path to store hex files with SUIT storage contents"
    )
    cmd_storage_arg_parser.add_argument(
        "--storage-address",
        required=False,
        type=lambda x: int(x, 0),
        default=ImageCreator.default_storage_address,
        help="Absolute address of the SUIT storage area",
    )
    cmd_storage_arg_parser.add_argument(
        "--config-file",
        required=False,
        default=None,
        help="Path to KConfig file",
    )
    cmd_storage_arg_parser.add_argument(
        "--soc",
        required=False,
        type=str,
        default="nrf54h20",
        help="SoC device (nrf54h20 or nrf9280)",
    )

    cmd_update_arg_parser = subparsers.add_parser(
        UPDATE_CMD, help="Generate files needed for Secure Domain update", parents=[parent_parser]
    )

    cmd_update_arg_parser.add_argument(
        "--update-candidate-info-address",
        required=False,
        type=lambda x: int(x, 0),
        default=ImageCreator.default_update_candidate_info_address,
        help="Address of SUIT storage update candidate info.",
    )
    cmd_update_arg_parser.add_argument(
        "--dfu-max-caches",
        required=False,
        type=int,
        default=ImageCreator.default_dfu_max_caches,
        help="Maximum number of caches, allowed to be passed inside update candidate info.",
    )
    cmd_update_arg_parser.add_argument("--input-file", required=True, help="SUIT envelope in binary format")
    cmd_update_arg_parser.add_argument(
        "--storage-output-file", required=True, help="SUIT storage output file in HEX format"
    )
    cmd_update_arg_parser.add_argument(
        "--dfu-partition-output-file", required=True, help="DFU partition output file in HEX format"
    )
    cmd_update_arg_parser.add_argument(
        "--dfu-partition-address", required=True, type=lambda x: int(x, 0), help="Start address of DFU partition"
    )

    arguments = parser.parse_args()

    logger.debug(f"Received arguments: {arguments}")

    sys.path.insert(0, os.path.join(arguments.zephyr_base, "scripts", "dts", "python-devicetree", "src"))

    configuration = read_configurations(arguments.core, arguments.target)

    if arguments.command == TEMPLATE_CMD:
        if arguments.version_file is not None:
            configuration.update(read_version_file(arguments.version_file))
        configuration["output_envelope"] = arguments.output_suit
        configuration["artifacts_folder"] = arguments.artifacts_folder
        output_suit_content = render_template(arguments.template_suit, configuration)
        with open(arguments.output_suit, "w") as output_file:
            output_file.write(output_suit_content)

    elif arguments.command == STORAGE_CMD:
        ImageCreator.create_files_for_boot(
            input_files=arguments.input_envelope,
            storage_output_directory=arguments.storage_output_directory,
            storage_address=arguments.storage_address,
            config_file=arguments.config_file,
            soc=arguments.soc,
        )
    elif arguments.command == UPDATE_CMD:
        ImageCreator.create_files_for_update(
            input_file=arguments.input_file,
            storage_output_file=arguments.storage_output_file,
            dfu_partition_output_file=arguments.dfu_partition_output_file,
            update_candidate_info_address=arguments.update_candidate_info_address,
            dfu_partition_address=arguments.dfu_partition_address,
            dfu_max_caches=arguments.dfu_max_caches,
        )
