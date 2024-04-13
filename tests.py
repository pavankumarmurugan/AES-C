# This file contains tests for the AES implementation in C.
# The tests are written in Python and utilize the ctypes library to invoke the
# C functions. Each test compares the output of the C function with the output
# of the corresponding Python function from
# https://github.com/boppreh/aes.git

import ctypes
import random
import pytest
import aes.aes as python_aes

# Load the C AES library
c_aes = ctypes.CDLL('./rijndael.so')
# Create an instance of the Python AES class
p_aes = python_aes.AES(b'\x00' * 16)

def generate_random_block():
    return bytes([random.randint(0, 255) for _ in range(16)])


@pytest.mark.parametrize('_', range(3))
def test_aes_encrypt_and_decrypt_block(_):
    # Generate a random 16-byte block and key
    random_block = generate_random_block()
    random_key = generate_random_block()
    print('Random block:', random_block, 'Random key:', random_key)

    # Convert the random block and key to ctypes buffers
    block_buffer = ctypes.create_string_buffer(random_block)
    key_buffer = ctypes.create_string_buffer(random_key)

    # Encrypt using the C function
    c_aes.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)
    c_encryption_address = c_aes.aes_encrypt_block(block_buffer, key_buffer)
    c_encryption_result = ctypes.string_at(c_encryption_address, 16)
    c_aes.my_free(c_encryption_address)

    # Encrypt using the Python function
    python_aes_instance = python_aes.AES(random_key)
    python_encryption_result = python_aes_instance.encrypt_block(random_block)

    assert c_encryption_result == bytes(python_encryption_result)

    # Decrypt using the C function
    c_aes.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)
    c_decryption_address = c_aes.aes_decrypt_block(c_encryption_result, key_buffer)
    c_decryption_result = ctypes.string_at(c_decryption_address, 16)
    c_aes.my_free(c_decryption_address)

    # Decrypt using the Python function
    python_decryption_result = python_aes_instance.decrypt_block(python_encryption_result)

    assert c_decryption_result == bytes(python_decryption_result)

    # Assert the original block matches the decrypted result
    assert random_block == c_decryption_result