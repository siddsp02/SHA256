import ctypes
from ctypes import POINTER, c_char, c_char_p, c_size_t, c_uint32

sha256_lib = ctypes.CDLL("../sha256.dll")

BLOCK_SIZE = 64
HASH_SIZE = 32

sha256_init = sha256_lib.sha256_init
sha256_update = sha256_lib.sha256_update
sha256_digest = sha256_lib.sha256_digest


class sha256(ctypes.Structure):
    _fields_ = [
        ("size", c_size_t),
        ("block", c_char * BLOCK_SIZE),
        ("hash", c_uint32 * (HASH_SIZE // ctypes.sizeof(c_uint32))),
    ]


sha256_init.argtypes = (c_char_p, c_size_t)
sha256_init.restype = sha256

sha256_update.argtypes = (POINTER(sha256), c_char_p, c_size_t)

sha256_digest.argtypes = (POINTER(sha256), POINTER(c_char))
sha256_digest.restype = POINTER(c_char)
