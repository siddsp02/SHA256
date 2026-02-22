#include "sha256.h"

#define ROTR32(x, n) ((x >> n) | (x << (32 - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define S1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define s0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ (x >> 3))
#define s1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10))

#define MIN(a, b) (a) < (b) ? (a) : (b)
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

static void get_blocks(uint32_t *w, const char *block) {
    size_t i;
    memcpy(w, block, 16 * sizeof(uint32_t));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    for (i = 0; i < 16; ++i)
        w[i] = U32REVBYTES(w[i]);
#endif
    for (i = 16; i < BLOCK_SIZE; ++i)
        w[i] = s1(w[i - 2]) + w[i - 7] + s0(w[i - 15]) + w[i - 16];
}

static void sha256_round(uint32_t *H, const char *ptr) {
    uint32_t a, b, c, d, e, f, g, h, i, t1, t2, w[BLOCK_SIZE];
    a = H[0], b = H[1], c = H[2], d = H[3];
    e = H[4], f = H[5], g = H[6], h = H[7];
    get_blocks(w, ptr);
    for (i = 0; i < BLOCK_SIZE; ++i) {
        t1 = h + S1(e) + CH(e, f, g) + K[i] + w[i];
        t2 = S0(a) + MAJ(a, b, c);
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

/* This function is less than ideal, because it only updates one block
   at at time. This will later be changed/optimized so as many blocks
   for a buffer will be processed all at once. The recursive definition
   is also less than ideal, but works because of simplicity. */
void sha256_update(sha256_t *obj, const char *msg, size_t size) {
    if (size == 0)
        return;
    size_t remaining, processed;
    remaining = obj->size % BLOCK_SIZE;
    processed = MIN(size, BLOCK_SIZE - remaining);
    memcpy(obj->block + remaining, msg, processed);
    obj->size += processed;
    if ((remaining + processed) < BLOCK_SIZE)
        return;
    sha256_round(obj->hash, obj->block);
    sha256_update(obj, msg + processed, size - processed);
}

sha256_t sha256_init(const char *msg, size_t size) {
    const uint32_t H[] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    sha256_t obj = (sha256_t) { 0 };
    memcpy(obj.hash, H, sizeof(H));
    sha256_update(&obj, msg, size);
    return obj;
}

char *sha256_digest(const sha256_t *obj, char *out) {
    size_t remaining, pad, n;
    uint32_t H[8];
    remaining = obj->size % BLOCK_SIZE;
    pad = BLOCK_SIZE * -(-(remaining + 9) / BLOCK_SIZE);
    char msg[BLOCK_SIZE * 2] = { 0 };
    memcpy(msg, obj->block, remaining);
    memcpy(H, obj->hash, sizeof(H));
    msg[remaining] = 1 << 7;
    n = obj->size * 8;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    n = U64REVBYTES(n);
#endif
    memcpy(msg + (pad - 8), &n, sizeof(n));
    for (size_t t = 0; t < pad/BLOCK_SIZE; ++t)
        sha256_round(H, msg + t*BLOCK_SIZE);
    memcpy(out, H, sizeof(H));
    return out;
}
