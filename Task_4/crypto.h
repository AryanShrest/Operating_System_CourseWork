#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

/* A minimal symmetric XOR cipher used to demonstrate confidentiality
 * of data in transit for this coursework. XOR encryption is easy to
 * break with known-plaintext attacks and is NOT suitable for real
 * security-critical systems - this trade-off is discussed in the
 * Task 4 documentation. A production system should use an
 * established library implementation of AES-GCM or ChaCha20-Poly1305
 * instead. */

#define SESSION_KEY "OS_SECURITY_2026_KEY"

/* Encrypts/decrypts `len` bytes of `data` in place using the XOR
 * stream defined by `key`. Calling this function twice with the same
 * key restores the original data (XOR is its own inverse). */
void xor_crypt(char *data, size_t len, const char *key);

#endif /* CRYPTO_H */
