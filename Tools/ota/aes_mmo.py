"""
References:
    https://github.com/andrebdo/c-crumbs/blob/master/aes-mmo.h
    https://github.com/Cognosec/SecBee/blob/master/ZigBee%20Crypto/zigbee_crypt.c >> cannot cope with large messages!

     * Reference:
 * ZigBee specification, document 05-3474-21, Aug 2015,
 * section B.6 Block-Cipher-Based Cryptographic Hash Function.


 to test: run aes_mmo_test.py

 """

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCKSIZE = 16


def congru(l, b, c):
    """ Solve l+1+k = b (mod c), returning k"""
    for i in range(0, c):
        if (((l + 1 + i) - b) % c) == 0:
            return int(i)

    raise Exception


def aes_mmo_hash(message):
    """ function returning a 128-bit AES-MMO hash as specified in
    ZigBee specification, document 05-3474-21, Aug 2015,
    Section B.6 Block-Cipher-Based Cryptographic Hash Function.


    """

    input_len = len(message)

    assert input_len < 22**BLOCKSIZE

    output = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    # Make Copy
    input = message[:]

    # Here we append a bit '1', followed by appending 7 '0' bits
    input.append(0x80)

    if input_len < ((2**BLOCKSIZE) / 8):

        # Solve l+1+k = 7n (mod 8n)
        # where l = length of input message
        # n = block size, in octets
        # k = amount of '0' bits to extend
        # Note; the leftover is always 7 bits, which we already have added above (0x80)
        extension = congru(input_len * 8, (7 * BLOCKSIZE), (8 * BLOCKSIZE))

        input.extend([0x00] * int(extension / 8))

        assert (extension % 8) == 7

        # Form the padded message M' by right-concatenating to the resulting string the n-bit
        # string that is equal to the binary representation of the integer l.
        input.append(((input_len * 8) >> 8) & 0xff)
        input.append(((input_len * 8) >> 0) & 0xff)
    else:

        # Solve l + 1 + k = 5n (mod 8n)
        # where l = length of input message
        # n = block size, in octets
        # k = amount of '0' bits to extend
        extension = congru(input_len * 8, (5 * BLOCKSIZE), (8 * BLOCKSIZE))

        input.extend([0x00] * int((extension / 8)))

        assert (extension % 8) == 7

        # Form the padded message M' by right-concatenating to the resulting string the 2n-bit
        # string that is equal to the binary representation of the integer l and right-concatenating to
        # the resulting string the n-bit all-zero bit string.
        input.append(((input_len * 8) >> 24) & 0xff)
        input.append(((input_len * 8) >> 16) & 0xff)
        input.append(((input_len * 8) >> 8) & 0xff)
        input.append(((input_len * 8) >> 0) & 0xff)
        input.append(0x00)
        input.append(0x00)

    # Pad to mod 16
    if len(input) % BLOCKSIZE != 0:
        input.extend([0x00] * (BLOCKSIZE - len(input) % BLOCKSIZE))

    assert len(input) % BLOCKSIZE == 0

    # Parse the padded message M' as M1 || M2|| .. || Mt where each message block Mi is an n-octet string.

    length_left = len(input)
    x = 0
    y = BLOCKSIZE
    while length_left != 0:
        key = bytes(bytearray(output[:]))

        # select 16 octets
        cipher_in = bytearray(input[x:y])

        assert len(cipher_in) == 16

        cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())
        encryptor = cipher.encryptor()
        result = encryptor.update(bytes(cipher_in)) + encryptor.finalize()
        output = bytearray(result)

        for j in range(0, BLOCKSIZE):
            output[j] ^= cipher_in[j]

        length_left -= BLOCKSIZE
        x += BLOCKSIZE
        y += BLOCKSIZE

    return output
