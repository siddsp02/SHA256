#ifndef SHA256_H
#include <stdio.h>
#include <stdint.h>
#include "array.h"

#define BLOCK_SIZE 64
#define HASH_SIZE 8 * sizeof(uint32_t)

#define ROTR32(a, n) ((a >> n) | (a << (32 - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define BS0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define BS1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define LS0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ (x >> 3))
#define LS1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10))

#define U32REVBYTES(x) (                                                       \
    ((x >> 24) & 0x000000ff) | ((x <<  8) & 0x00ff0000) |                      \
    ((x >>  8) & 0x0000ff00) | ((x << 24) & 0xff000000)                        \
)
#define U64REVBYTES(x) (                                                       \
    ((x >> 56) & 0x00000000000000ffULL) | ((x >> 40) & 0x000000000000ff00ULL) |\
    ((x >> 24) & 0x0000000000ff0000ULL) | ((x >>  8) & 0x00000000ff000000ULL) |\
    ((x << 56) & 0xff00000000000000ULL) | ((x << 40) & 0x00ff000000000000ULL) |\
    ((x << 24) & 0x0000ff0000000000ULL) | ((x <<  8) & 0x000000ff00000000ULL)  \
)

static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

typedef uint32_t uint256_t[8];

#define print_u256(val) do {        \
    for (size_t i = 0; i < 8; ++i)  \
        printf("%#8x ", ((uint32_t *) (val))[i]); \
    puts("");                       \
} while (0)

#define PADDED_LENGTH(size) (BLOCK_SIZE * -(-(size + 9) / BLOCK_SIZE))

// Returns a heap-allocated copy of a statically-sized local array.
#define static_copy(A) memcpy(malloc(sizeof(A)), A, sizeof(A))

char *sha256(array(char) *msg);

#endif /* SHA256_H */