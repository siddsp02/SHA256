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
} message;

message message_create(size_t size, const char *buf);
char *sha256(message *msg);
#endif