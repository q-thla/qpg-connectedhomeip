#!/usr/bin/env python3

import argparse
import sys
import os
import logging
import shutil
import subprocess

DESCRIPTION = """\
Turn a Matter application build hex-file into an OTA image by:
- adding metadata to Qorvo datastructures
- applying compression
- adding matter-header
"""

SCRIPT_PATH = os.path.dirname(__file__)
CRCFIRMWARE_PATH = f"{SCRIPT_PATH}/crcFirmware.py"
HEX2BIN_PATH = f"{SCRIPT_PATH}/hex2bin.py"
COMPRESSFIRMWARE_PATH = f"{SCRIPT_PATH}/compressFirmware.py"

if not os.path.isfile(os.path.join(SCRIPT_PATH, "crypto_utils.py")):
    CRCFIRMWARE_PATH = os.getenv("QORVO_CRCFIRMWARE_PATH", CRCFIRMWARE_PATH)
    HEX2BIN_PATH = os.getenv("QORVO_HEX2BIN_PATH", HEX2BIN_PATH)
    COMPRESSFIRMWARE_PATH = os.getenv("QORVO_COMPRESSFIRMWARE_PATH", COMPRESSFIRMWARE_PATH)


def parse_command_line_arguments():
    """Parse command-line arguments"""
    def any_base_int(string):
        return int(string, 0)
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument("--chip_config_header",
                        help="path to Matter config header file")

    parser.add_argument("--chip_root",
                        help="Path to root Matter directory")

    parser.add_argument("--in_file",
                        help="Path to input file to format to Matter OTA fileformat")

    parser.add_argument("--out_file",
                        help="Path to output file (.ota file)")
    parser.add_argument('-vn', '--version', type=any_base_int, help='Software version (numeric)', default=1)
    parser.add_argument('-vs', '--version-str', help='Software version (string)', default="1.0")
    parser.add_argument('-vid', '--vendor-id', help='Vendor ID (string)', default=None)
    parser.add_argument('-pid', '--product-id', help='Product ID (string)', default=None)

    args = parser.parse_args()
    if not args.chip_root:
        logging.error("Supply Matter root directory")
        sys.exit(-1)
    else:
        assert os.path.isdir(args.chip_root), f"The path specified as chip root is not a directory: {args.chip_root}"

    if not args.in_file:
        logging.error("Supply an input file")
        sys.exit(-1)
    else:
        assert os.path.isfile(args.in_file), f"The path specified as input file is not a file: {args.in_file}"

    if not args.out_file:
        logging.error("Supply an output file")
        sys.exit(-1)

    return args


def run_script(command: str):
    """ run a python script using the current interpreter """
    subprocess.check_output(f"{sys.executable} {command}", shell=True)


def extract_vid_and_pid(chip_config_header: str):
    """ determine vendorid/product id from a CHIP project's headers """
    vid = None
    pid = None
    with open(chip_config_header, 'r', encoding='utf-8') as config_file:
        lines = config_file.readlines()

    for line in lines:
        if 'CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID' in line and '#define' in line:
            vid = line.split()[2]
        if 'CHIP_DEVICE_CONFIG_DEVICE_PRODUCT_ID' in line and '#define' in line:
            pid = line.split()[2]

    if vid is None or pid is None:
        print(f"Error retrieving PID and VID from configuration file ({chip_config_header})")
        sys.exit(-1)
    return vid, pid


def determine_example_project_config_header(args):
    """ Determine the CHIPProjectConfig.h path of a matter-sourcetree based example application."""
    if 'lighting' in args.in_file:
        project_name = 'lighting-app'
    elif 'lock' in args.in_file:
        project_name = 'lock-app'
    elif 'persistent' in args.in_file:
        project_name = 'persistent-storage'
    elif 'shell' in args.in_file:
        project_name = 'shell'
    else:
        raise Exception(f"Unable to deduce which example project {args.in_file} belongs to!")

    return f"{args.chip_root}/examples/{project_name}/qpg/include/CHIPProjectConfig.h"


def determine_vid_and_pid_values(args):
    """ Decide which vendorid and productid the user wants to use """
    if not args.vendor_id and not args.product_id:
        used_chip_config_header = args.chip_config_header or determine_example_project_config_header(args)
        return extract_vid_and_pid(used_chip_config_header)
    if args.chip_config_header is not None:
        raise Exception("Either specify vid/pid or chip config header")
    assert args.vendor_id and args.product_id, "Both vendor id and product id are needed"
    return (args.vendor_id, args.product_id)


def create_ota_payload(input_path: str):
    """ Run Qorvo ota processing steps """
    input_base_path = os.path.splitext(input_path)[0]
    intermediate_crc_added = f"{input_base_path}-crc.hex"
    intermediate_crc_added_binary = f"{input_base_path}-crc.bin"
    intermediate_compressed_binary_path = f"{input_base_path}.compressed.bin"

    # crcFirmware modifies in place, so copy
    shutil.copyfile(input_path, intermediate_crc_added)

    run_script(f"{CRCFIRMWARE_PATH} --add_crc --add_padding"
               f" --hex {intermediate_crc_added} --license_offset 0x4800"
               f" --section1 0x00004900:0xffffffff --section2 0x800:0x1000"
               f" --start_addr_area 0x4000000"
               )
    run_script(f"{HEX2BIN_PATH} {intermediate_crc_added} {intermediate_crc_added_binary}")
    run_script(f"{COMPRESSFIRMWARE_PATH} --add_crc"
               f" --input {intermediate_crc_added_binary}"
               " --license_offset 0x47f0 --ota_offset 0x9c000"
               f" --output {intermediate_compressed_binary_path} --page_size 0x200 --sector_size 0x400"
               )
    return intermediate_compressed_binary_path


def main():
    """ Main """

    args = parse_command_line_arguments()

    (vid, pid) = determine_vid_and_pid_values(args)

    # Qorvo specific OTA preparation
    intermediate_compressed_binary_path = create_ota_payload(args.in_file)

    # Matter header wrapping
    tool_args = f"create -v {vid} -p {pid} -vn {args.version} -vs {args.version_str} -da sha256 "
    run_script(f"{args.chip_root}/src/app/ota_image_tool.py {tool_args} "
               f"{intermediate_compressed_binary_path} {args.out_file}")


if __name__ == "__main__":
    main()
