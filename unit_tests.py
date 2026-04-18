import ctypes

# Load the shared library
try:
    aes_lib = ctypes.CDLL('./rijndael.so')
    print("Successfully loaded rijndael.so")
except OSError as e:
    print(f"Could not load the library. Did you run 'make'?")
    exit(1)

buffer = b'\x00\x01\x02\x03\x04\x05\x06\x07'
buffer += b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
block = ctypes.create_string_buffer(buffer)

rijndael.sub_bytes(block, 0) # 0 = AES_BLOCK_128


result = ctypes.string_at(rijndael.aes_encrypt_block(plaintext, key), 16)