#ifndef AUTH_H
#define AUTH_H

/* Very small "user database" for demonstration purposes.
  */

#define MAX_USERS 10

typedef struct {
    char username[32];
    char password_hash[65]; /* hex digest string */
} UserRecord;

/* Initialise the built-in user table. Must be called once at
 * server start-up before authenticate() is used. */
void auth_init(void);

/* Returns 1 if username/password combination is valid, 0 otherwise. */
int authenticate(const char *username, const char *password);

/* Very small non-cryptographic hashing helper used to avoid storing
 * plaintext passwords in the source. NOT suitable for production use -
 * discussed further in the security analysis document. */
void simple_hash(const char *input, char *output_hex);

#endif /* AUTH_H */
