#!/usr/bin/env python3

import sys
import os

def extract_vid_and_pid(chip_root, project_name):
    filename = "{}/examples/{}/qpg/include/CHIPProjectConfig.h".format(chip_root, project_name)
    vid = None
    pid = None
    with open(filename, 'r') as config_file:
        lines = config_file.readlines()
        
    for line in lines:
        if 'CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID' in line and '#define' in line:
            vid = line.split()[2]
        if 'CHIP_DEVICE_CONFIG_DEVICE_PRODUCT_ID' in line and '#define' in line:
            pid = line.split()[2]

    if vid is None or pid is None:
        print("Error retrieving PID and VID from configuration file ({})".format(filename))
        exit(-1)
    return vid, pid
        
def exec_image_tool(chip_root, in_file, out_file, vn, vs):

    if 'lighting' in in_file:
        project_name = 'lighting-app'
    elif 'lock' in in_file:
        project_name = 'lock-app'
    elif 'persistent' in in_file:
        project_name = 'persistent-storage'
    elif 'shell' in in_file:
        project_name = 'shell'
    vid, pid = extract_vid_and_pid(chip_root, project_name)
    args = "create -v {} -p {} -vn {} -vs {} -da sha256".format(vid, pid, vn, vs)
    cmd = "{}/src/app/ota_image_tool.py {} {} {}".format(chip_root, args, in_file, out_file)
    os.system(cmd)

# Take cmd line parameters <chip_root> <in> <out> and call CHIP OTA header generation script
def main():
    if len(sys.argv) < 4:
        print("Wrong number of parameters. Usage: generate_ota_img.py <chip_root> <in_hex> <out_ota> ({})".format(len(sys.argv)))
        exit(-1)
        
    chip_root = sys.argv[1]
    in_hex = sys.argv[2]
    out_ota = sys.argv[3]
    exec_image_tool(chip_root, in_hex, out_ota, 1, "1.0")
        
if __name__ == "__main__":
    main()
