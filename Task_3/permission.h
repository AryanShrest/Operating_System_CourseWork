/* permission.h - simulated Unix-style owner/group/others permissions
 * (Task 3 requirement: "File permission system: read, write, execute
 * for owner/group/others"). Permissions are simulated in software
 * rather than relying on the real filesystem's permission bits, so
 * behaviour is identical and demonstrable regardless of OS/filesystem.
 */
#ifndef PERMISSION_H
#define PERMISSION_H

#define MAX_FILENAME 64
#define PERM_STR_LEN 4   /* e.g. "rwx" + NUL */

typedef struct {
    char filename[MAX_FILENAME];
    char owner[32];
    char group[16];
    char owner_perm[PERM_STR_LEN];   /* e.g. "rwx" */
    char group_perm[PERM_STR_LEN];   /* e.g. "r--" */
    char others_perm[PERM_STR_LEN];  /* e.g. "---" */
} FilePermission;

/* Registers a new file with default permissions (owner: rw-, group:
 * r--, others: ---), owned by `owner`/`group`. Called by file_ops.c
 * whenever a file is created. */
void permission_create_entry(const char *filename, const char *owner, const char *group);

/* Removes a file's permission entry (called on delete). */
void permission_remove_entry(const char *filename);

/* Returns 1 if `username` (member of `usergroup`) may perform `action`
 * ('r', 'w', or 'x') on `filename`; 0 otherwise. Files with no
 * registered permission entry are denied by default (fail closed). */
int permission_check(const char *filename, const char *username,
                      const char *usergroup, char action);

/* Prints the permission block for a file, in the format:
 *   File: <name>
 *   Owner : <owner>      Group : <group>
 *   Permissions
 *     Owner : rwx
 *     Group : r--
 *     Others: ---
 */
void permission_view(const char *filename);

/* Interactive: lets the owner (or an admin-group user) change the
 * owner/group/others permission triads for a file. */
void permission_set(const char *filename, const char *current_username,
                     const char *current_usergroup);

/* Non-interactive variant used by main.c to seed default demo files
 * with specific permissions at first run. */
void permission_set_direct(const char *filename, const char *owner_perm,
                            const char *group_perm, const char *others_perm);

#endif /* PERMISSION_H */
