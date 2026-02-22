#include "sha256.h"

int main(int argc, char *argv[]) {
    sha256_t s = sha256_init(argv[1], strlen(argv[1]));
    uint32_t out[8];
    sha256_digest(&s, (char *) out);
    for (size_t i = 0; i < 8; ++i)
        printf("%#8lx ", out[i]);
    printf("\n");
}