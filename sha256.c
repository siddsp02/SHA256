/**
 * An implementation of the SHA256 cryptographic hashing algorithm in C.
 * The following code is my own (and took lots of time debugging)!
 *
 * References:
 *   - https://helix.stormhub.org/papers/SHA-256.pdf
 */

#include "sha256.h"
#include <stdarg.h>
#include <assert.h>

#define BLOCK_SIZE 64
#define BLOCK_SIZE_BITS BLOCK_SIZE * 8
#define HASH_SIZE 8 * sizeof(uint32_t)

#define ROTR32(a, n) ((a >> n) | (a << (32 - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define BS0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define BS1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define LS0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ (x >> 3))
#define LS1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10))

#define BLOCK_COUNT(msg) (msg->size / BLOCK_SIZE)
#define U32REVBYTES(x) (                                                        \
    ((x >> 24) & 0x000000ff) | ((x <<  8) & 0x00ff0000) |                       \
    ((x >>  8) & 0x0000ff00) | ((x << 24) & 0xff000000)                         \
)
#define U64REVBYTES(x) (                                                        \
    ((x >> 56) & 0x00000000000000ffULL) | ((x >> 40) & 0x000000000000ff00ULL) | \
    ((x >> 24) & 0x0000000000ff0000ULL) | ((x >>  8) & 0x00000000ff000000ULL) | \
    ((x << 56) & 0xff00000000000000ULL) | ((x << 40) & 0x00ff000000000000ULL) | \
    ((x << 24) & 0x0000ff0000000000ULL) | ((x <<  8) & 0x000000ff00000000ULL)   \
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

/*
 * Pads a message to a multiple of 512 bits or 64 bytes in length,
 * with a 1 bit appended as well as the size being added to the
 * end as a 64-bit little-endian integer.
 */
static void pad_bytes(message *msg) {
    uint64_t i, new_size, old_size;
    old_size = msg->size;
    new_size = BLOCK_SIZE * -(-(old_size + 9) / BLOCK_SIZE);
    assert(new_size > old_size && new_size % 64 == 0);
    msg->buf = realloc(msg->buf, new_size);
    msg->buf[msg->size] = 1 << 7; // Append 1-bit to end of message.
    memset(msg->buf + msg->size + 1, 0, new_size - msg->size + 1);
    msg->size = new_size;
    old_size = U64REVBYTES(old_size * 8);  // Get bit-length and reverse.
    memcpy(msg->buf + new_size - 8, &old_size, sizeof(uint64_t));
}

/*
 * Gets the blocks of a message in the form of 64 32-bit words.
 */
static uint32_t *get_blocks(const char *msg) {
    uint32_t i, *w;
    w = malloc(BLOCK_SIZE * sizeof(uint32_t));
    memcpy(w, msg, 16 * sizeof(uint32_t));
    for (i = 0; i < 16; ++i)
        w[i] = U32REVBYTES(w[i]);
    for (i = 16; i < BLOCK_SIZE; ++i)
        w[i] = LS1(w[i - 2]) + w[i - 7] + LS0(w[i - 15]) + w[i - 16];
    return w;
}

/*
 * Returns the SHA256 hash of a message when given its contents.
 * Messages are automatically padded as part of the specification
 * of this algorithm.
 */
char *sha256(message *msg) {
    uint32_t a, b, c, d, e, f, g, h, i, n, t, t1, t2, *w;
    uint32_t H[] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    pad_bytes(msg);
    n = BLOCK_COUNT(msg);
    for (t = 0; t < n; ++t) {
        a = H[0], b = H[1], c = H[2], d = H[3];
        e = H[4], f = H[5], g = H[6], h = H[7];
        w = get_blocks(msg->buf + (t * BLOCK_SIZE));
        for (i = 0; i < 64; ++i) {
            t1 = h + BS1(e) + CH(e, f, g) + K[i] + w[i];
            t2 = BS0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        H[0] += a, H[1] += b, H[2] += c, H[3] += d;
        H[4] += e, H[5] += f, H[6] += g, H[7] += h;
        free(w);
    }
    char *msg_hash = malloc(HASH_SIZE);
    memcpy(msg_hash, H, HASH_SIZE);
    return msg_hash;
}

int main() {
    size_t i, j, sizes[] = {3, 56, 1000000};
    message m[3];
    char *hash;
    const char v0[] = {0x61, 0x62, 0x63};
    const char v1[] = {
        0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65,
        0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67,
        0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
        0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b,
        0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d,
        0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f,
        0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71,
    };
    for (i = 0; i < 3; ++i) {
        m[i].size = sizes[i];
        m[i].buf = malloc(sizes[i]);
    }
    // Initialize values.
    memcpy(m[0].buf, v0, 3);
    memcpy(m[1].buf, v1, 56);
    memset(m[2].buf, 0x61, 1000000);  // One million of 0x61
    // Print the hashes of the test vectors.
    for (i = 0; i < 3; ++i) {
        hash = sha256(&m[i]);
        for (j = 0; j < 8; ++j)
            printf("%08x ", ((uint32_t *) hash)[j]);
        printf("\n");
        free(m[i].buf);
    }
    return 0;
}