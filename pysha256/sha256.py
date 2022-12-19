# !usr/bin/env python3

"""
An implementation of the SHA256 cryptographic hashing algorithm in Python.
The following code is my own.

References:
    - https://helix.stormhub.org/papers/SHA-256.pdf
"""

# fmt: off

import struct
import sys

UINT32_MAX = (1 << 32) - 1

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def rotr32(a: int, n: int) -> int:
    return ((a >> n) | a << (32 - n))


def ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)


def maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def bs0(x: int) -> int:
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)


def bs1(x: int) -> int:
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)


def ls0(x: int) -> int:
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)


def ls1(x: int) -> int:
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10)


def addmu32(x: int, y: int) -> int:
    return (x + y) & UINT32_MAX


def pad_bytes(msg: bytearray) -> None:
    new_size = 64 * -(-(len(msg) + 9) // 64)
    assert new_size > len(msg) and new_size % 64 == 0
    old_size = len(msg)
    msg.extend(bytes(1) * (new_size - old_size))
    msg[old_size] = 1 << 7
    struct.pack_into(">Q", msg, len(msg) - 8, old_size * 8)


def get_blocks(msg: bytes) -> list[int]:
    w = [0] * 64
    w[:16] = (w for w, in struct.iter_unpack(">L", msg))
    for i in range(16, 64):
        w[i] = (ls1(w[i - 2]) + w[i - 7] + ls0(w[i - 15]) + w[i - 16]) & UINT32_MAX
    return w


def sha256(msg: bytearray) -> list[int]:
    """Returns the SHA256 hash of a message when given its contents.

    Messages are automatically padded as part of the specification
    of this algorithm.
    """
    H = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]
    pad_bytes(msg)
    for t in range(0, len(msg), 64):
        a, b, c, d, e, f, g, h = H
        w = get_blocks(msg[t:t+64])
        for i in range(64):
            t1 = (h + bs1(e) + ch(e, f, g) + K[i] + w[i]) & UINT32_MAX
            t2 = (bs0(a) + maj(a, b, c)) & UINT32_MAX
            h, g, f, e = g, f, e, (d + t1) & UINT32_MAX
            d, c, b, a = c, b, a, (t1 + t2) & UINT32_MAX
        H[:] = map(addmu32, H, [a, b, c, d, e, f, g, h])
    return H


def main() -> None:
    msg = bytearray(sys.argv[1].encode("ascii"))
    hash = sha256(msg)
    for value in hash:
        print(f"{value:08x}", end=" ")
    print()


if __name__ == "__main__":
    main()
