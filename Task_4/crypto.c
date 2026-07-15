#include <string.h>
#include "crypto.h"

void xor_crypt(char *data, size_t len, const char *key) {
    size_t key_len = strlen(key);
    if (key_len == 0) return;

    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}
