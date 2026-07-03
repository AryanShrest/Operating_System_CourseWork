/* auth.h - user accounts and login (Task 3 requirement: "User
 * authentication mechanism"). Passwords are stored in plaintext in
 * users.txt for this academic demonstration -- see the note in auth.c
 * for why a real system must hash them instead.
 */
#ifndef AUTH_H
#define AUTH_H

#define MAX_USERNAME 32
#define MAX_PASSWORD 32
#define MAX_GROUP    16
#define MAX_LOGIN_ATTEMPTS 3

typedef struct {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char group[MAX_GROUP];
} User;

/* Currently logged-in identity, valid after auth_login() succeeds. */
extern char current_user[MAX_USERNAME];
extern char current_group[MAX_GROUP];

/* Creates users.txt with sample accounts if it does not already exist. */
void auth_ensure_users_file(void);

/* Runs the login prompt (username + masked password), allowing up to
 * MAX_LOGIN_ATTEMPTS tries. Returns 1 on success (current_user /
 * current_group are set), 0 if the user exhausted their attempts. */
int auth_login(void);

#endif /* AUTH_H */
