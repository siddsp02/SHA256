#include "sha256.h"

#define PRINT_OUTPUT(buf) do {      \
    for (size_t i = 0; i < 8; ++i)  \
        printf("%#8lx ", buf[i]);   \
    printf("\n");                   \
} while (0)

const uint32_t outputs[3][8] = {
    {0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad},
    {0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039, 0xa33ce459, 0x64ff2167, 0xf6ecedd4, 0x19db06c1},
    {0xcdc76e5c, 0x9914fb92, 0x81a1c7e2, 0x84d73e67, 0xf1809a48, 0xa497200e, 0x046d39cc, 0xc7112cd0},
};

int main() {
    char m1[] = {
        0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65,
        0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67,
        0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
        0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b,
        0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d,
        0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f,
        0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71,
    };
    char m2[1000] = { [0 ... 999] = 0x61};
    uint32_t out[8] = { 0 };
    
    sha256_t s;
    sha256_init(&s, m1, 3);
    
    sha256_digest(&s, (char *) out);
    PRINT_OUTPUT(out);
    assert(memcmp(out, outputs[0], 32) == 0);
    
    sha256_update(&s, m1 + 3, 53);
    memset(out, 0, sizeof(out));
    
    sha256_digest(&s, (char *) out);
    PRINT_OUTPUT(out);
    assert(memcmp(out, outputs[1], 32) == 0);

    sha256_init(&s, m2, 1000);
    for (size_t i = 0; i < 999; ++i)
        sha256_update(&s, m2, 1000);

    sha256_digest(&s, (char *) out);
    PRINT_OUTPUT(out);
    assert(memcmp(out, outputs[2], 32) == 0);
    return 0;
}
