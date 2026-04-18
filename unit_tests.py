import ctypes
import os
import sys

# Add the 'aes' subdirectory to the search path so we import the module, not the folder
sys.path.append(os.path.join(os.path.dirname(__file__), 'aes'))
import aes as aes_py


# Load the shared library
try:
    aes_lib = ctypes.CDLL('./rijndael.so')
    print("Successfully loaded rijndael.so")
except OSError as e:
    print(f"Could not load the library. Did you run 'make'?")
    exit(1)

# Define the global variable
AES_BLOCK_128 = 0


# Define the function prototypes from the header file
# LLM Assisted Autocomplete: TODO = needs revision
aes_lib.sub_bytes.argtypes = [ctypes.c_void_p, ctypes.c_int]
aes_lib.shift_rows.argtypes = [ctypes.c_void_p, ctypes.c_int]
aes_lib.mix_columns.argtypes = [ctypes.c_void_p, ctypes.c_int]
aes_lib.add_round_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
aes_lib.expand_key.argtypes = [ctypes.c_void_p, ctypes.c_int]
aes_lib.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte * 176)
aes_lib.invert_sub_bytes.argtypes = [ctypes.c_void_p, ctypes.c_int]
aes_lib.invert_shift_rows.argtypes = [ctypes.c_void_p, ctypes.c_int]
aes_lib.invert_mix_columns.argtypes = [ctypes.c_void_p, ctypes.c_int]

def encryption_tests(operation_name, c_func, py_func):
    print(f"Testing operation: {operation_name}...", end="")
    test_input = os.urandom(16)

    # Prepare the C buffer using the SAME random input
    c_block = ctypes.create_string_buffer(test_input)

    # Prepare Python state
    py_block = aes_py.bytes2matrix(test_input)

    if operation_name.lower() == "addroundkey":
        round_key = os.urandom(16)
        c_round_key = ctypes.create_string_buffer(round_key)
        c_func(c_block, c_round_key, AES_BLOCK_128)
        py_func(py_block, aes_py.bytes2matrix(round_key))
    else:
        c_func(c_block, AES_BLOCK_128)
        py_func(py_block)
    
    # Extract exactly 16 bytes from the C buffer (raw includes null terminator)
    c_result_bytes = c_block.raw[:16]
    py_result_bytes = aes_py.matrix2bytes(py_block)

    if c_result_bytes == py_result_bytes:
        print("PASSED")
    else:
        print("FAILED")
        print(f"  Input:  {test_input.hex()}")
        print(f"  C Res:  {c_result_bytes.hex()}")
        print(f"  Py Res: {py_result_bytes.hex()}")

def decryption_tests(operation_name, c_func, py_func):
    print(f"Testing operation: {operation_name}...", end="")
    test_input = os.urandom(16)

    # Prepare the C buffer using the SAME random input
    c_block = ctypes.create_string_buffer(test_input)

    # Prepare Python state
    py_block = aes_py.bytes2matrix(test_input)

    c_func(c_block, AES_BLOCK_128)
    py_func(py_block)
    
    # Extract exactly 16 bytes from the C buffer (raw includes null terminator)
    c_result_bytes = c_block.raw[:16]
    py_result_bytes = aes_py.matrix2bytes(py_block)

    if c_result_bytes == py_result_bytes:
        print("PASSED")
    else:
        print("FAILED")
        print(f"  Input:  {test_input.hex()}")
        print(f"  C Res:  {c_result_bytes.hex()}")
        print(f"  Py Res: {py_result_bytes.hex()}")


if __name__ == "__main__":
    encryption_tests("SubBytes", aes_lib.sub_bytes, aes_py.sub_bytes)
    encryption_tests("ShiftRows", aes_lib.shift_rows, aes_py.shift_rows)
    encryption_tests("MixColumns", aes_lib.mix_columns, aes_py.mix_columns)
    encryption_tests("AddRoundKey", aes_lib.add_round_key, aes_py.add_round_key)

    decryption_tests("InvSubBytes", aes_lib.invert_sub_bytes, aes_py.inv_sub_bytes)
    decryption_tests("InvShiftRows", aes_lib.invert_shift_rows, aes_py.inv_shift_rows)
    decryption_tests("InvMixColumns", aes_lib.invert_mix_columns, aes_py.inv_mix_columns)
    