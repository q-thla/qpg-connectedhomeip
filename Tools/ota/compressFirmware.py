"""
This tool will compress a binary format firmware file with lzma after applying padding up to a page
size multiple. .
This tool will also calculate the CRC over the relevant part of the binary file and patch it
into the Loaded User License. Alternatively, if secure boot is targetted, a signature will be
created and injected into the Extended User License
"""
import argparse
import os
import struct
import codecs
import sys
import logging
import hashlib
import lzma

from binascii import crc32
from ecdsa import NIST256p, NIST192p


if os.path.isfile(os.path.join(os.path.dirname(__file__), "crypto_utils.py")):
    # In the Matter DK, all python modules are exported to this script's directory
    import crypto_utils as crypto_utils
else:
    # When running from the Qorvo codebase, use the dependencies from original paths
    moduleroot = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    sys.path.append(os.path.join(moduleroot, "comps"))
    from crypto_utils import crypto_utils
    sys.path.remove(os.path.join(moduleroot, "comps"))

    # Determine if we are an .exe or not
    if not getattr(sys, 'frozen', False):
        current_dir = os.path.dirname(os.path.realpath(__file__))
        parent_dir = os.path.dirname(current_dir)
        sys.path.append(os.path.join(parent_dir, "..", "..", "..", "..", "..", "Env", "vless", "gppy_vless", "inf"))
        from getEnvVersion import getEnvVersion

        try:
            envVersion = getEnvVersion()
            envPath = os.path.join(parent_dir, "..", "..", "..", "..", "..", "Env", envVersion)
        except Exception as e:
            # Fallback to ENV_PATH
            print("WARNING: getEnvVersion() failed, falling back to ENV_PATH")
            envPath = os.path.abspath(os.environ.get('ENV_PATH'))

        print("abs: %s" % os.path.abspath(os.path.join(envPath, "gppy", "tools", "sec")))
        sys.path.append(os.path.join(envPath, "gppy", "tools", "sec"))

from aes_mmo import aes_mmo_hash
from x25519 import x25519_sign_and_return_response


# CONSTANTS
USER_LICENSE_CRC_VALUE_OFFSET = 0x10
USER_LICENSE_VPP_OFFSET = 0x1C

USER_LICENSE_LOAD_COMPLETED_OFFSET = 0x78
USER_LICENSE_FRESHNESS_COUNTER_OFFSET = 0x7F

EXTENDED_USER_LICENSE_OFFSET = 0x80
EXTENDED_USER_LICENSE_SIGNATURE_OFFSET = (EXTENDED_USER_LICENSE_OFFSET + 0x28)
EXTENDED_USER_LICENSE_SIGNATURE_SIZE = 64

EXTENDED_USER_LICENSE_SECTION_1_ADDRESS_OFFSET = 0x98
EXTENDED_USER_LICENSE_SECTION_1_SIZE_OFFSET = (EXTENDED_USER_LICENSE_SECTION_1_ADDRESS_OFFSET + 4)
EXTENDED_USER_LICENSE_SECTION_2_ADDRESS_OFFSET = (EXTENDED_USER_LICENSE_SECTION_1_SIZE_OFFSET + 4)
EXTENDED_USER_LICENSE_SECTION_2_SIZE_OFFSET = (EXTENDED_USER_LICENSE_SECTION_2_ADDRESS_OFFSET + 4)

LICENSE_SIZE = 0x100

CRC_START_ADDRESS_MSB_OOB = 0xFFFF
CRC_START_ADDRESS_LSB_OOB = 0xFF
CRC_TYPE_32BIT_CRC = 1
CRC_SIZE_OOB = 0X00000000

EXTENDED_USER_LICENSE_SECTION_NOT_IN_USE = 0xFFFFFFFF


def get_section_sizes(args):

    # Read file contents
    args.hexdata = b''
    with open(args.input, 'rb') as fr:
        data = fr.read()
        while data:
            args.hexdata += data
            data = fr.read()

    # Extract license
    args.hexdata_ul = bytearray(args.hexdata[int(args.license_offset, 16):
                                             int(args.license_offset, 16) + int(args.sector_size, 16)])

    # calculate locations in flash
    args.section1_addr = struct.unpack_from('I', args.hexdata_ul, EXTENDED_USER_LICENSE_SECTION_1_ADDRESS_OFFSET)[0]
    args.section1_size = struct.unpack_from('I', args.hexdata_ul, EXTENDED_USER_LICENSE_SECTION_1_SIZE_OFFSET)[0]
    args.section2_addr = struct.unpack_from('I', args.hexdata_ul, EXTENDED_USER_LICENSE_SECTION_2_ADDRESS_OFFSET)[0]
    args.section2_size = struct.unpack_from('I', args.hexdata_ul, EXTENDED_USER_LICENSE_SECTION_2_SIZE_OFFSET)[0]


def split_binary(args):

    logging.info("Splitting binary file in parts")

    # If jumptables are present
    if (args.section2_addr != EXTENDED_USER_LICENSE_SECTION_NOT_IN_USE):
        with open(args.jumptableFile, 'wb') as fw:
            # section1 starts after the userlicense, compensate for in offset calculation
            section1_user_license_skip_length = 0x100
            start_offset = args.section1_addr - int(args.license_offset,16) - section1_user_license_skip_length
            jumptables_start_offset = 0x800 - start_offset
            fw.write(args.hexdata[jumptables_start_offset:jumptables_start_offset + args.section2_size])
        logging.info("Written jumptables to %s" % args.jumptableFile)
    with open(args.licenseFile, 'wb') as fw:
        fw.write(bytes(args.hexdata_ul))
    logging.info("Written license to %s" % args.licenseFile)
    with open(args.appBinFile, 'wb') as fw:
        fw.write(bytes(args.hexdata[int(args.license_offset, 16):len(args.hexdata)]))
    logging.info("Written application to %s" % args.appBinFile)


def add_crc(args):

    # Gather data to calculate checksum over
    data = bytearray()

    # Add application part section 1
    data.extend(args.hexdata_app)

    # Add application part section 2
    if (args.section2_addr != EXTENDED_USER_LICENSE_SECTION_NOT_IN_USE):
        with open(args.jumptableFile, 'rb') as fr:
            args.hexdata_jt = bytearray(fr.read())
        data.extend(args.hexdata_jt)

    # Add license part
    for i in range(USER_LICENSE_VPP_OFFSET, LICENSE_SIZE):
        # Mask out Load Complete MW
        if (i == USER_LICENSE_LOAD_COMPLETED_OFFSET
           or i == USER_LICENSE_LOAD_COMPLETED_OFFSET + 1
           or i == USER_LICENSE_LOAD_COMPLETED_OFFSET + 2
           or i == USER_LICENSE_LOAD_COMPLETED_OFFSET + 3
           or i == USER_LICENSE_FRESHNESS_COUNTER_OFFSET):
            # Mask out freshness counter entry
            data.append(0x00)
        else:
            data.append(args.hexdata_ul[i])

    crcvalue = (~crc32(memoryview(data)) ^ 0xFFFFFFFF) & 0xFFFFFFFF

    # Write checksum to license area
    struct.pack_into('IHBBI', args.hexdata_ul, USER_LICENSE_CRC_VALUE_OFFSET, crcvalue,
                     CRC_START_ADDRESS_MSB_OOB, CRC_START_ADDRESS_LSB_OOB, CRC_TYPE_32BIT_CRC, CRC_SIZE_OOB)
    logging.info("Packed CRC %s" % hex(crcvalue))


def calculate_signature(image, pemfile_path, password):
    """
    calculate_signature calculates the signature over a specified image using the private key
    contained in the specified file. The password for the file is also required.
    """
    # Retrieve information from PEM file
    logging.info("Reading PEM file: %s" % os.path.basename(pemfile_path))

    (pem_curve, private_key, public_key) = crypto_utils.getPrivatePublicKeysFromPEMFile(pemfile_path,
                                                                                        password)

    # Assure correct curves and hashes are being used together

    if pem_curve == "secp192r1":
        curve = NIST192p
        hash_function = hashlib.sha1
    elif pem_curve == "secp256r1":
        curve = NIST256p
        hash_function = hashlib.sha256
    else:
        assert False

    logging.info("Using signing curve: %s" % curve.name)
    logging.info("PEM file has curve: %s" % pem_curve)

    # print "INFO: Using signing curve: %x" % curve
    # print "INFO: PEM file has curve: %x" % pem_curve

    logging.info("Hashing and signing image")
    signature = crypto_utils.signMessage(image, private_key, curve=curve, hashfunc=hash_function)

    logging.info("=====================================")
    logging.info("Signature to be put in user license:")
    logging.info(crypto_utils.getCCodeBuffer(signature, "signature"))
    # crypto_utils.printCCodeBuffer(private_key, "private_key")
    logging.info("=====================================")
    logging.info("Public key to be put in bootloader:")
    logging.info(crypto_utils.getCCodeBuffer(public_key, "public_key"))
    logging.info("=====================================")

    return signature, public_key, curve, hash_function


def add_signature(args):

    # Gather data to calculate signature
    image = b''

    # Add application part section 1
    for byte in args.hexdata_app:
        image += struct.pack("B", byte)

    if args.x25519:
        """ The ROM_aes_mmo_update function, which is used to hash the section, requires a multiple of 16-bytes as
        data to be hashed, so if the size of the section is not a multiple of 16 bytes, we add zero padding to get
        to this multiple"""

        remainder = len(image) % 16
        if remainder != 0:
            for i in range(0, 16 - remainder):
                image += struct.pack("B", 0x00)

            logging.info("Section size not a multiple of 16 as required by ROM_aes_mmo_update, adding %d zero bytes"
                         % (16 - remainder))

        assert len(image) % 16 == 0

    # Add application part section 2 if needed
    if (args.section2_addr != EXTENDED_USER_LICENSE_SECTION_NOT_IN_USE):
        with open(args.jumptableFile, 'rb') as fr:
            args.hexdata_jt = bytearray(fr.read())
        for byte in args.hexdata_jt:
            image += struct.pack("B", byte)

    if args.x25519:
        """ The ROM_aes_mmo_update function, which is used to hash the section, requires a multiple of 16-bytes as
        data to be hashed, so if the size of the section is not a multiple of 16 bytes, we add zero padding to get
        to this multiple"""

        remainder = len(image) % 16
        if remainder != 0:
            for i in range(0, 16 - remainder):
                image += struct.pack("B", 0x00)

            logging.info("Section size not a multiple of 16 as required by ROM_aes_mmo_update, adding %d zero bytes"
                         % (16 - remainder))

        assert len(image) % 16 == 0

    # Add license part
    start_load_completed_mw_offset = USER_LICENSE_LOAD_COMPLETED_OFFSET
    end_load_completed_mw_offset = USER_LICENSE_LOAD_COMPLETED_OFFSET + 4
    start_freshness_counter_offset = USER_LICENSE_FRESHNESS_COUNTER_OFFSET - 3
    stop_freshness_counter_offset = USER_LICENSE_FRESHNESS_COUNTER_OFFSET + 1
    for i in range(USER_LICENSE_VPP_OFFSET, EXTENDED_USER_LICENSE_SIGNATURE_OFFSET):
        if (start_load_completed_mw_offset <= i < end_load_completed_mw_offset) or \
           (start_freshness_counter_offset <= i < stop_freshness_counter_offset):
            pass
        else:
            image += struct.pack("B", args.hexdata_ul[i])

    """
    add_signature adds a signature over a specified image to the specified Intel HEX file object.
    """
    if args.x25519:
        aes_mmo_hash_buf = bytearray(image)

        print("AES-MMO hashing %d bytes total" % len(aes_mmo_hash_buf))

        aes_mmo_result = aes_mmo_hash(aes_mmo_hash_buf)

        print("aes_mmo_hash:")
        print(' '.join('0x{:02x}'.format(x) for x in aes_mmo_result))

        f = open(args.x25519_private_key_binfile, "rb")
        dump = f.read()

        signature = x25519_sign_and_return_response(aes_mmo_result, bytearray(dump))
    else:
        signature, public_key, curve, hash_function = calculate_signature(
            image,
            args.pem,
            codecs.encode(args.pem_password, 'UTF-8')
        )

        # Verify that image is signed correctly
        if crypto_utils.verifyMessage(image, public_key, signature, curve=curve, hashfunc=hash_function):
            logging.info("SUCCESS: Message OK")
        else:
            logging.error("Message NOK")

    # set the signature in the binary license
    signature = bytearray(signature)
    args.hexdata_ul[
        EXTENDED_USER_LICENSE_SIGNATURE_OFFSET:
        EXTENDED_USER_LICENSE_SIGNATURE_OFFSET + EXTENDED_USER_LICENSE_SIGNATURE_SIZE
    ] = signature


def fill_license(args):

    logging.info("Filling the compressed license")

    with open(args.output, 'rb') as fr:
        args.hexdata_app = fr.read()

    # Organize ota image as follows:
    # 0x1000 bytes before ota_space is reserved for jumptables
    # first sector will be used for user license
    # the actual compressed image starts afterwards and length should be set to compressed image size
    section1_addr = int(args.ota_offset, 16) + int(args.sector_size, 16)
    section1_size = os.path.getsize(args.output)
    section2_size = args.section2_size
    if args.section2_addr != EXTENDED_USER_LICENSE_SECTION_NOT_IN_USE:
        section2_addr = int(args.ota_offset, 16) - section2_size
    else:
        section2_addr = args.section2_addr

    # pack the calculated values into the binary data + set vpp to ota_area location offset
    struct.pack_into('IIII', args.hexdata_ul, EXTENDED_USER_LICENSE_SECTION_1_ADDRESS_OFFSET,
                     section1_addr, section1_size, section2_addr, section2_size)
    logging.info("Packed sections in compressed license: section1 %s:%s, section2 %s,%s" %
                 (hex(section1_addr), hex(section1_size), hex(section2_addr), hex(section2_size)))

    if (args.add_crc):
        add_crc(args)
    if (args.pem) or (args.x25519):
        add_signature(args)

    with open(args.licenseFile, 'wb') as fw:
        fw.write(bytes(args.hexdata_ul))


def combine_files(args):

    logging.info("Combining all binary files to one output file")

    # Combine the files
    with open(args.output, 'wb') as fw:
        if args.section2_addr != EXTENDED_USER_LICENSE_SECTION_NOT_IN_USE:
            with open(args.jumptableFile, 'rb') as fr:
                fw.write(fr.read())
        if args.license_offset:
            with open(args.licenseFile, 'rb') as fr:
                fw.write(fr.read())
        fw.write(args.hexdata_app)


def parse_command_line_arguments():
    """
    parse_command_line_arguments parses the command line arguments of the signfw
    application.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("--input",
                        help="path to bin file to be compressed")
    parser.add_argument("--output",
                        help="output bin file to be written")

    parser.add_argument("--add_crc",
                        help="add crc calculation",
                        action='store_true')

    parser.add_argument("--license_offset",
                        help="offset relative to the start of the file where the user license begins")
    parser.add_argument("--ota_offset",
                        help="offset of the ota area relative to the start of the flash")

    parser.add_argument("--page_size",
                        help="the page size used in the target device flash")
    parser.add_argument("--sector_size",
                        help="the sector size used in the target device flash")

    parser.add_argument("--pem",
                        help="path to PEM file to be signed")
    parser.add_argument("--pem_password",
                        help="optional PEM file password")

    parser.add_argument("--x25519",
                        help="use AES-MMO + x25519 signing",
                        action='store_true')

    parser.add_argument("--x25519_private_key_binfile",
                        help="private key used for signing")

    args = parser.parse_args()
    if not args.input:
        logging.error("Supply BIN file path")
        sys.exit(-1)

    if args.pem:
        if not args.pem_password:
            logging.error("Supply PEM file password path")
            sys.exit(-1)

    if not args.output:
        args.output = os.path.splitext(args.input)[0].append(".compressed").append(os.path.splitext(args.input)[1])
        logging.warning("Setting default output file = %s" % args.output)

    if not args.license_offset:
        logging.info("Not using license approach")

    return args



def lzma_compress(input_file, output_file):
    """ compress with lzma and add a header containing the uncompressed size """

    dictionarySize = 1 << 16
    lc = 3 # -lc3 : set number of literal context bits : [0, 8] : default = 3
    lp = 0 # -lp0 : set number of literal pos bits : [0, 4] : default = 0
    pb = 2 # -pb2 : set number of pos bits : [0, 4] : default = 2

    ota_filters = [
        {"id": lzma.FILTER_LZMA1,
            "preset": 7 | lzma.PRESET_EXTREME,
            "dict_size": dictionarySize,
            "lc": 3, #lc: Number of literal context bits.
            "lp": 0,  #lp: Number of literal position bits. The sum lc + lp must be at most 4.
            "pb": 2, #pb: Number of position bits; must be at most 4.
        },
    ]

    properties = (pb * 5 + lp) * 9 + lc
    assert properties == 0x5d, f"properties is {properties:x} instead"

    compressor = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=ota_filters)
    with open(output_file, mode='wb') as output_handle, \
        open(input_file, 'rb') as input_handle:
        input_data = input_handle.read()
        print(f"length input data: {len(input_data):x}")
        header = struct.pack("<BIQ",
            properties,  #properties
            dictionarySize, #dictionarySize
            len(input_data), #decompressedSize
        )
        output_handle.write(header)
        output_handle.write(compressor.compress(input_data))
        output_handle.write(compressor.flush())

def pad_bin_file(page_size, input_file: str, output_file: str):
    """ pad the file to a page size multiple by adding 0's """

    with open(output_file, mode='wb') as output_handle, \
        open(input_file, 'rb') as input_handle:
        input_data = input_handle.read()
        print(f"length input data: {len(input_data):x}")
        output_handle.write(input_data)
        bytes_in_incomplete_page = len(input_data) % page_size
        if bytes_in_incomplete_page != 0:
            padding_size = page_size - bytes_in_incomplete_page
            output_handle.write(b'\x00' * padding_size)

def main():
    """
    main is the entry point of the compressfw application.
    """
    logging.basicConfig(level=logging.INFO)
    args = parse_command_line_arguments()

    # Set file variables
    args.licenseFile = os.path.splitext(args.input)[0] + ".license.bin"
    args.appBinFile = os.path.splitext(args.input)[0] + ".application.bin"
    args.jumptableFile = os.path.splitext(args.input)[0] + ".jumptables.bin"
    args.paddedBinFile = os.path.splitext(args.input)[0] + ".padded.bin"

    ###############################################

    # First need to split off the jumptables and user license if needed
    if args.license_offset:
        get_section_sizes(args)
        split_binary(args)
        file_to_pad = args.appBinFile
    else:
        file_to_pad = args.input

    pad_bin_file(int(args.page_size, 16), file_to_pad, args.paddedBinFile)

    lzma_compress(args.paddedBinFile, args.output)

    if args.license_offset:
        # Transform the user license into the compressed user license by adjusting content
        fill_license(args)

        # Then add the jumptables and the license again
        combine_files(args)


if __name__ == "__main__":
    main()
