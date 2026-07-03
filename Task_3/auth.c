/* auth.c
 *
 * SECURITY NOTE: users.txt stores passwords in plaintext. This is a
 * deliberate simplification for an academic demonstration so the file
 * can be inspected and marked easily. A production system must never
 * do this -- it should store only a salted hash (e.g. bcrypt/Argon2)
 * and compare hashes, never the raw password, so that even someone
 * with read access to the user database cannot recover passwords.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include "auth.h"
#include "config.h"

char current_user[MAX_USERNAME]  = "";
char current_group[MAX_GROUP]    = "";

void auth_ensure_users_file(void) {
    FILE *f = fopen(USERS_FILE, "r");
    if (f) { fclose(f); return; }

    f = fopen(USERS_FILE, "w");
    if (!f) { perror("Could not create users.txt"); return; }
    /* username password group */
    fprintf(f, "admin password123 admin\n");
    fprintf(f, "john hello123 staff\n");
    fprintf(f, "alice abc123 staff\n");
    fclose(f);
}

/* Reads a line of input with the terminal echo turned off, printing a
 * '*' for every character typed instead (so the user still gets
 * visual feedback that keystrokes registered, without revealing the
 * password on screen). Falls back to a plain read if stdin is not an
 * interactive terminal (e.g. input piped in for automated testing). */
static void read_masked(char *buf, size_t size) {
    if (!isatty(fileno(stdin))) {
        if (fgets(buf, (int)size, stdin)) {
            buf[strcspn(buf, "\n")] = '\0';
        } else {
            buf[0] = '\0';
        }
        return;
    }

    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= (unsigned)~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    size_t len = 0;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        if (c == 127 || c == '\b') {          /* backspace */
            if (len > 0) { len--; printf("\b \b"); fflush(stdout); }
            continue;
        }
        if (len + 1 < size) {
            buf[len++] = (char)c;
            putchar('*');
            fflush(stdout);
        }
    }
    buf[len] = '\0';
    putchar('\n');

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

/* Looks up a username in users.txt; returns 1 and fills *out on match. */
static int find_user(const char *username, User *out) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 0;

    User u;
    int found = 0;
    while (fscanf(f, "%31s %31s %15s", u.username, u.password, u.group) == 3) {
        if (strcmp(u.username, username) == 0) {
            *out = u;
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

int auth_login(void) {
    printf("%s\n", UI_LINE);
    printf("      SECURE FILE MANAGEMENT SYSTEM\n");
    printf("%s\n\n", UI_LINE);

    for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
        char username[MAX_USERNAME];
        char password[MAX_PASSWORD];

        printf("Username : ");
        fflush(stdout);
        if (!fgets(username, sizeof(username), stdin)) return 0;
        username[strcspn(username, "\n")] = '\0';

        printf("Password : ");
        fflush(stdout);
        read_masked(password, sizeof(password));

        User u;
        if (find_user(username, &u) && strcmp(u.password, password) == 0) {
            strncpy(current_user, u.username, MAX_USERNAME - 1);
            strncpy(current_group, u.group, MAX_GROUP - 1);
            printf("\nLogin Successful!\n\n");
            return 1;
        }

        printf("\nInvalid Username or Password.\n");
        if (attempt < MAX_LOGIN_ATTEMPTS)
            printf("Attempts remaining: %d\n\n", MAX_LOGIN_ATTEMPTS - attempt);
    }

    printf("\nToo many failed attempts. Exiting for security.\n");
    return 0;
}
