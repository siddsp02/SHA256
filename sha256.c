/**
 * An implementation of the SHA256 cryptographic hashing algorithm in C.
 * The following code is my own (and took lots of time debugging)!
 *
 * References:
 *   - https://helix.stormhub.org/papers/SHA-256.pdf
 */

#include "sha256.h"
#include <assert.h>


/**
 * Pads a message to a multiple of 512 bits or 64 bytes in length,
 * with a 1 bit appended as well as the size being added to the
 * end as a 64-bit big-endian integer.
 */
static void pad_bytes(message *msg) {
    uint64_t new_size, old_size;
    // Calculate the size to resize the input message to
    old_size = msg->size;
    new_size = BLOCK_SIZE * -(-(old_size + 9) / BLOCK_SIZE);
    assert(new_size > old_size && new_size % 64 == 0);
    // Reallocate and zero-initialize remaining memory.
    msg->buf = realloc(msg->buf, new_size);
    msg->buf[old_size] = 1 << 7; // Append one-bit.
    memset(msg->buf + old_size + 1, 0, new_size - old_size + 1);
    msg->size = new_size;
    old_size *= 8;
    // Append the length of the message as a 64-bit big-endian integer.
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    old_size = U64REVBYTES(old_size);
#endif
    memcpy(msg->buf + new_size - 8, &old_size, sizeof(uint64_t));
}

/**
 * Gets the blocks of a message in the form of 64 32-bit words.
 */
static uint32_t *get_blocks(const char *msg) {
    uint32_t i, *w;
    w = malloc(BLOCK_SIZE * sizeof(uint32_t));
    memcpy(w, msg, 16 * sizeof(uint32_t));
    // Reverse the bytes of each word if the byte order is little-endian.
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    for (i = 0; i < 16; ++i)
        w[i] = U32REVBYTES(w[i]);
#endif
    for (i = 16; i < BLOCK_SIZE; ++i)
        w[i] = LS1(w[i - 2]) + w[i - 7] + LS0(w[i - 15]) + w[i - 16];
    return w;
}

const char *sha256(message *msg) {
    uint32_t a, b, c, d, e, f, g, h, i, n, t, t1, t2, *w;
    uint32_t H[] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    pad_bytes(msg);
    n = BLOCK_COUNT(msg);
    /* Iterate through the original message in chunks of 64 bytes,
       and generate the block values as an array of 64 32-bit words
       which are then used in the hashing process (SHA-rounds). */
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
    memcpy(msg->hash, H, HASH_SIZE);
    return ((const char *) msg->hash);
}
