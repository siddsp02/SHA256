#include "sha256.h"

int main(int argc, char *argv[]) {
    size_t i, len;
    message msg;
    len = strlen(argv[1]);
    msg.size = len;
    msg.buf = malloc(len);
    memcpy(msg.buf, argv[1], len);
    sha256(&msg);
    for (i = 0; i < 8; ++i)
        printf("%08x ", msg.hash[i]);
    puts("");
    return 0;
}