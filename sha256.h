#ifndef SHA256_H
#define SHA256_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

typedef struct {
    size_t size;
    char *buf;
    uint32_t hash[8];
} message;

/**
 * Returns the SHA256 hash of a message when given its contents.
 * Messages are automatically padded as part of the specification
 * of this algorithm. The hash field of the message is updated,
 * and a const pointer to it is returned to it for convenience.
 */
const char *sha256(message *msg);
#endif
