
import os
import sys
# from pysodium import crypto_scalarmult_curve25519, crypto_scalarmult_BYTES, randombytes


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.join(os.path.dirname(os.path.abspath(__file__)))

    return os.path.join(base_path, relative_path)


x25519_sign_binary_path = resource_path("x25519_sign.exe")
x25519_scalarmult_binary_path = resource_path("x25519_scalarmult.exe")


def x25519_generate_ephemeral_private_key():

    eph_private_key = bytearray(os.urandom(32))

    assert len(eph_private_key) == 32

    # Clamp
    eph_private_key[0] &= 0xf8
    eph_private_key[31] &= 0x7f
    eph_private_key[31] |= 0x40

    return eph_private_key


def x25519_generate_public_key_from_private_key(private_key):

    # Generate public key from pysodium
    # nine = bytearray([0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    # # public_key = crypto_scalarmult_curve25519(bytes(private_key), bytes(nine))
    # public_key = nine

    # newdata = bytearray(public_key)

    # return bytearray(public_key)

    f = open("input.bin", "wb")

    assert len(private_key) == 32

    f.write(private_key)

    f.close()

    cmd = x25519_scalarmult_binary_path
    cmd += " input.bin output.bin"

    os.system(cmd)

    os.remove("input.bin")

    f = open("output.bin", "rb")

    response = f.read(32)

    f.close()

    os.remove("output.bin")

    return bytearray(response)


def x25519_sign(challenge, eph_private_key, private_key):

    f = open("input.bin", "wb")

    assert len(challenge) == 32
    assert len(eph_private_key) == 32
    assert len(private_key) == 32

    f.write(private_key)
    f.write(eph_private_key)
    f.write(challenge)

    f.close()

    cmd = x25519_sign_binary_path
    cmd += " input.bin output.bin"

    os.system(cmd)

    os.remove("input.bin")

    f = open("output.bin", "rb")

    response = f.read(32)

    f.close()

    os.remove("output.bin")

    return bytearray(response)


def x25519_sign_and_return_response(aes_mmo_result, private_key):

    assert len(private_key) == 32

    # Generate Public Key
    public_key = x25519_generate_public_key_from_private_key(private_key)

    # newdata = bytearray(public_key)
    print("Curve25519 Public Key to be put in SB:")
    print(' '.join('0x{:02x}'.format(x) for x in public_key))

    # Generate Ephemeral Private Key
    eph_private_key = x25519_generate_ephemeral_private_key()

    # Generate Ephemeral Public Key
    eph_public_key = x25519_generate_public_key_from_private_key(eph_private_key)

    # Construct challenge value by concatenating the same AES-MMO hash to produce 32 bytes
    aes_mmo_hash_buf = bytearray(aes_mmo_result) + bytearray(aes_mmo_result)

    # sign
    x25519_response = x25519_sign(aes_mmo_hash_buf, eph_private_key, private_key)

    # concatenate response and ephemeral public key, which fit right into the ENUL
    x25519_response += eph_public_key

    assert len(x25519_response) == 64

    return x25519_response


def x25519_sign_and_fill_in_signature(ihex_file, aes_mmo_result, private_key, signature_address):

    x25519_response = x25519_sign_and_return_response(aes_mmo_result, private_key)

    for idx, bytevalue in enumerate(x25519_response):
        ihex_file[signature_address + idx] = bytevalue

    print("Writing signature + ephemeral public key to offset 0x%x" % signature_address)
