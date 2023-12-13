#ifndef SHA256_H
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include "array.h"

typedef uint32_t uint256_t[8];

#define print_u256(val) do {        \
    for (size_t i = 0; i < 8; ++i)  \
        printf("%#8x ", ((uint32_t *) (val))[i]); \
    puts("");                       \
} while (0)

char *sha256(array(char) msg);
char *sha256_file(FILE *fp);

#endif /* SHA256_H */