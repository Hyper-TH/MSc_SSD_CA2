import ctypes
import os
import sys

# Add the 'aes' subdirectory to the search path so we import the module, not the folder
sys.path.append(os.path.join(os.path.dirname(__file__), 'aes_reference'))
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
aes_lib.aes_encrypt_block.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
aes_lib.aes_encrypt_block.restype = ctypes.c_void_p
aes_lib.aes_decrypt_block.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
aes_lib.aes_decrypt_block.restype = ctypes.c_void_p

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
    
    passed = False
    # Extract exactly 16 bytes from the C buffer (raw includes null terminator)
    c_result_bytes = c_block.raw[:16]
    py_result_bytes = aes_py.matrix2bytes(py_block)

    if c_result_bytes == py_result_bytes:
        print("PASSED")
        passed = True
    else:
        print("FAILED")
        print(f"  Input:  {test_input.hex()}")
        print(f"  C Res:  {c_result_bytes.hex()}")
        print(f"  Py Res: {py_result_bytes.hex()}")
    return passed

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
        return True
    else:
        print("FAILED")
        print(f"  Input:  {test_input.hex()}")
        print(f"  C Res:  {c_result_bytes.hex()}")
        print(f"  Py Res: {py_result_bytes.hex()}")
        return False

def glue_tests(operation_name, c_func, py_func):
    print(f"Testing operation: {operation_name}...", end="")
    test_input = os.urandom(16)
    key = os.urandom(16)

    # Prepare the C buffers using the SAME random input
    c_block = ctypes.create_string_buffer(test_input)
    c_key = ctypes.create_string_buffer(key)

    c_func.restype = ctypes.c_void_p
    res_ptr = c_func(c_block, c_key, AES_BLOCK_128)
    
    if not res_ptr:
        print("FAILED (C function returned NULL)")
        return False
        
    c_result_bytes = ctypes.string_at(res_ptr, 16)
    py_result_bytes = py_func(test_input, key)

    if c_result_bytes == py_result_bytes:
        print("PASSED")
        return True
    else:
        print("FAILED")
        print(f"  Input:  {test_input.hex()}")
        print(f"  Key:    {key.hex()}")
        print(f"  C Res:  {c_result_bytes.hex()}")
        print(f"  Py Res: {py_result_bytes.hex()}")
        return False

# GEMINI'S IDEA for debugging the glue tests..
def test_key_expansion():
    print("Testing operation: Key Expansion...", end="")
    key = os.urandom(16)
    
    # C Expansion
    c_expanded_ptr = aes_lib.expand_key(key, AES_BLOCK_128)
    c_expanded = bytes(c_expanded_ptr.contents)
    
    # Python Expansion (Reference)
    py_aes = aes_py.AES(key)
    py_expanded = b"".join([aes_py.matrix2bytes(m) for m in py_aes._key_matrices])
    
    if c_expanded == py_expanded:
        print("PASSED")
        return True
    else:
        print("FAILED")
        print(f"  Key:      {key.hex()}")
        print(f"  C Size:   {len(c_expanded)}, Py Size: {len(py_expanded)}")
        print(f"  C First:  {c_expanded[:16].hex()} (Original Key)")
        print(f"  Py First: {py_expanded[:16].hex()} (Original Key)")
        return False

# TODO: Run three tests for each operation.
if __name__ == "__main__":
    results = []

    print("Running Unit Tests for AES Operations...\n")
    results.append(encryption_tests("SubBytes", aes_lib.sub_bytes, aes_py.sub_bytes))
    results.append(encryption_tests("ShiftRows", aes_lib.shift_rows, aes_py.shift_rows))
    results.append(encryption_tests("MixColumns", aes_lib.mix_columns, aes_py.mix_columns))
    results.append(encryption_tests("AddRoundKey", aes_lib.add_round_key, aes_py.add_round_key))

    print("\nRunning Unit Tests for AES Decryption Operations...\n")
    results.append(decryption_tests("InvSubBytes", aes_lib.invert_sub_bytes, aes_py.inv_sub_bytes))
    results.append(decryption_tests("InvShiftRows", aes_lib.invert_shift_rows, aes_py.inv_shift_rows))
    results.append(decryption_tests("InvMixColumns", aes_lib.invert_mix_columns, aes_py.inv_mix_columns))

    print("\nRunning Isolation Test for Key Expansion...\n")
    results.append(test_key_expansion())

    print("\nRunning Glue Tests for AES Encrypt/Decrypt...\n")
    # GEMINI'S NOTE: Lambda is used here to adapt the Python function to the expected signature for the glue test
    results.append(glue_tests("AES Encrypt Block", aes_lib.aes_encrypt_block, lambda p, k: aes_py.AES(k).encrypt_block(p)))
    results.append(glue_tests("AES Decrypt Block", aes_lib.aes_decrypt_block, lambda p, k: aes_py.AES(k).decrypt_block(p)))

    if not all(results):
        print("\n[!] CI Failure: One or more unit tests failed.")
        sys.exit(1)
    
    print("\n[+] All tests passed successfully.")
    sys.exit(0)