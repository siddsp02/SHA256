#include "sha256.h"

int main(int argc, char *argv[]) {
    array(char) buf = arr_new(char);
    for (char *c = argv[1]; *c; ++c)
        arr_push(buf, *c);
    char *hash = sha256(buf);
    print_u256(hash);
    arr_free(buf);
    return 0;
}
