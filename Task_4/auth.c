#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "auth.h"

static UserRecord g_users[MAX_USERS];
static int g_user_count = 0;

/* -------------------------------------------------------------------
 * simple_hash
 * ---------------------------------------------------------------
 * A lightweight, dependency-free hashing function (djb2 variant)
 * used only so plaintext passwords are never compared directly.
 * This is NOT cryptographically secure - it exists to demonstrate
 * the *pattern* of hash-then-compare authentication. In production
 * this would be replaced with bcrypt/argon2/SHA-256 from a vetted
 * crypto library (e.g. OpenSSL). This limitation is discussed in
 * the Task 4 security notes.
 * ------------------------------------------------------------- */
void simple_hash(const char *input, char *output_hex) {
    uint64_t hash = 5381;
    int c;
    const unsigned char *str = (const unsigned char *)input;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    /* Expand the 64-bit hash into a fixed-length hex string so it
     * "looks" like a digest and is a fixed comparable size. */
    snprintf(output_hex, 65, "%016llx%016llx%016llx%016llx",
             (unsigned long long)(hash ^ 0x1111111111111111ULL),
             (unsigned long long)(hash ^ 0x2222222222222222ULL),
             (unsigned long long)(hash ^ 0x3333333333333333ULL),
             (unsigned long long)(hash ^ 0x4444444444444444ULL));
}

static void add_user(const char *username, const char *password) {
    if (g_user_count >= MAX_USERS) return;
    strncpy(g_users[g_user_count].username, username, sizeof(g_users[0].username) - 1);
    simple_hash(password, g_users[g_user_count].password_hash);
    g_user_count++;
}

void auth_init(void) {
    g_user_count = 0;
    /* Demo accounts - in a real deployment these would be loaded
     * from a protected configuration file / database. */
    add_user("pradhan", "pradhan123");
    add_user("shrestha", "shrestha123");
    add_user("admin", "admin@2026");
}

int authenticate(const char *username, const char *password) {
    char hash[65];
    simple_hash(password, hash);

    for (int i = 0; i < g_user_count; i++) {
        if (strcmp(g_users[i].username, username) == 0 &&
            strcmp(g_users[i].password_hash, hash) == 0) {
            return 1;
        }
    }
    return 0;
}
