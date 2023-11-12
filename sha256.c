#include "sha256.h"

static void pad_bytes(array(char) *msg) {
    uint64_t newsize, oldsize;
    oldsize = len(*msg);
    newsize = PADDED_LENGTH(oldsize);
    assert(newsize > oldsize && newsize % 64 == 0);
    arr_resize((*msg), newsize);
    arr_data((*msg))->size = newsize;
    memset((*msg) + oldsize + 1, 0, newsize - oldsize + 1);
    (*msg)[oldsize] = 1 << 7;
    oldsize *= 8;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    oldsize = U64REVBYTES(oldsize);
#endif
    memcpy((*msg) + newsize - 8, &oldsize, sizeof(uint64_t));
}

static void get_blocks(uint32_t *w, char *msg) {
    size_t i;
    memcpy(w, msg, 16 * sizeof(uint32_t));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    for (i = 0; i < 16; ++i)
        w[i] = U32REVBYTES(w[i]);
#endif
    for (i = 16; i < BLOCK_SIZE; ++i)
        w[i] = LS1(w[i - 2]) + w[i - 7] + LS0(w[i - 15]) + w[i - 16];
}

char *(sha256)(array(char) *msg) {
    uint32_t a, b, c, d, e, f, g, h, i, n, t, t1, t2, w[BLOCK_SIZE];
    uint256_t H = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    pad_bytes(msg);
    n = (len((*msg)) / BLOCK_SIZE);
    for (t = 0; t < n; ++t) {
        a = H[0], b = H[1], c = H[2], d = H[3];
        e = H[4], f = H[5], g = H[6], h = H[7];
        get_blocks(w, (*msg) + t*BLOCK_SIZE);
        for (i = 0; i < BLOCK_SIZE; ++i) {
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
    }
    return static_copy(H);
}
