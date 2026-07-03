/* main.c
 * ST5004CEM - Operating Systems and Security - Task 3
 * File System Operations and Security
 *
 * Program flow: start -> login -> main menu -> chosen operation
 * (permission check -> perform op) -> back to menu -> logout/exit.
 * See README.md for the full walkthrough.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "config.h"
#include "auth.h"
#include "file_ops.h"
#include "permission.h"

/* -------------------------------------------------------------------
 * First-run setup: create the files/ directory, users.txt,
 * permissions.txt, and two sample files if they don't already exist,
 * so the system is immediately demonstrable.
 * ------------------------------------------------------------------- */
static void seed_file_if_missing(const char *filename, const char *content,
                                  const char *owner, const char *group,
                                  const char *owner_perm, const char *group_perm,
                                  const char *others_perm) {
    char path[128];
    snprintf(path, sizeof(path), "%s/%s", FILES_DIR, filename);

    FILE *check = fopen(path, "r");
    if (check) { fclose(check); return; }  /* already exists, leave it alone */

    FILE *f = fopen(path, "w");
    if (!f) return;
    fputs(content, f);
    fclose(f);

    permission_create_entry(filename, owner, group);
    permission_set_direct(filename, owner_perm, group_perm, others_perm);
}

static void init_system(void) {
    struct stat st = {0};
    if (stat(FILES_DIR, &st) == -1) mkdir(FILES_DIR, 0755);

    auth_ensure_users_file();

    FILE *plog = fopen(PERMISSIONS_FILE, "a"); if (plog) fclose(plog);

    seed_file_if_missing("report.txt",
        "Quarterly Report\nStatus: Draft\n",
        "admin", "staff", "rwx", "r--", "---");
    seed_file_if_missing("notes.txt",
        "Hello World\nOperating Systems\n",
        "admin", "staff", "rw-", "r--", "---");
}

/* -------------------------------------------------------------------
 * UI helpers -- deliberately plain (no colour/animation) to match a
 * classic terminal admin-tool look and keep every screen easy to
 * screenshot for the assignment deliverables.
 * ------------------------------------------------------------------- */
static void print_main_menu(void) {
    printf("\n%s\n", UI_LINE);
    printf("              MAIN MENU\n");
    printf("%s\n\n", UI_LINE);
    printf("1. Create File\n");
    printf("2. Read File\n");
    printf("3. Write File\n");
    printf("4. Delete File\n");
    printf("5. File Permissions\n");
    printf("6. Logout\n");
    printf("0. Exit\n\n");
    printf("Enter Choice: ");
    fflush(stdout);
}

static int read_choice(void) {
    char line[16];
    if (!fgets(line, sizeof(line), stdin)) return -1;
    return atoi(line);
}

static void read_filename_prompt(char *buf, size_t size) {
    printf("Enter filename: ");
    fflush(stdout);
    if (fgets(buf, (int)size, stdin)) buf[strcspn(buf, "\n")] = '\0';
    else buf[0] = '\0';
}

static void handle_permissions_menu(void) {
    char filename[MAX_FILENAME];
    read_filename_prompt(filename, sizeof(filename));
    permission_view(filename);

    printf("\nModify these permissions? (Y/N): ");
    fflush(stdout);
    char confirm[8];
    if (fgets(confirm, sizeof(confirm), stdin) &&
        (confirm[0] == 'Y' || confirm[0] == 'y')) {
        permission_set(filename, current_user, current_group);
    }
}

/* -------------------------------------------------------------------
 * Session loop -- runs after a successful login, until the user picks
 * Logout (returns to the login screen) or Exit (ends the program).
 * ------------------------------------------------------------------- */
static int run_session(void) {  /* returns 1 to logout (stay in program), 0 to exit */
    int choice = -1;
    while (choice != 0) {
        print_main_menu();
        choice = read_choice();

        switch (choice) {
            case 1: file_create(current_user, current_group); break;
            case 2: file_read(current_user, current_group);   break;
            case 3: file_write(current_user, current_group);  break;
            case 4: file_delete(current_user, current_group); break;
            case 5: handle_permissions_menu();                break;
            case 6:
                printf("\nLogging out...\n");
                return 1;
            case 0:
                printf("\nGoodbye.\n");
                return 0;
            default:
                printf("\nInvalid choice. Please select an option from the menu.\n");
        }
    }
    return 0;
}

int main(void) {
    init_system();

    for (;;) {
        if (!auth_login()) return 0;   /* exhausted login attempts */
        int keep_running = run_session();
        if (!keep_running) break;      /* Exit chosen inside session */
        /* otherwise: Logout was chosen -> loop back to auth_login() */
    }
    return 0;
}
