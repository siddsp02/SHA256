#ifndef SHA256_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define BLOCK_SIZE 64

typedef struct {
    size_t size;
    char block[BLOCK_SIZE];
    uint32_t hash[8];
} sha256_t;


void sha256_update(sha256_t *obj, const char *msg, size_t size);
sha256_t sha256_init(const char *msg, size_t size);
char *sha256_digest(const sha256_t *obj, char *out);

#endif /* SHA256_H */