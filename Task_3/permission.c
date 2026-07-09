/* permission.c
 *
 * Permissions are stored one-per-line in permissions.txt as:
 *   filename owner group owner_perm group_perm others_perm
 * e.g.
 *   report.txt admin staff rwx r-- ---
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "permission.h"
#include "config.h"

#define MAX_ENTRIES 256

static int load_entries(FilePermission *entries) {
    FILE *f = fopen(PERMISSIONS_FILE, "r");
    if (!f) return 0;

    int count = 0;
    FilePermission p;
    while (count < MAX_ENTRIES &&
           fscanf(f, "%63s %31s %15s %3s %3s %3s",
                  p.filename, p.owner, p.group,
                  p.owner_perm, p.group_perm, p.others_perm) == 6) {
        entries[count++] = p;
    }
    fclose(f);
    return count;
}

static void save_entries(FilePermission *entries, int count) {
    FILE *f = fopen(PERMISSIONS_FILE, "w");
    if (!f) { perror("Could not write permissions.txt"); return; }
    for (int i = 0; i < count; i++) {
        fprintf(f, "%s %s %s %s %s %s\n",
                entries[i].filename, entries[i].owner, entries[i].group,
                entries[i].owner_perm, entries[i].group_perm, entries[i].others_perm);
    }
    fclose(f);
}

static int find_index(FilePermission *entries, int count, const char *filename) {
    for (int i = 0; i < count; i++)
        if (strcmp(entries[i].filename, filename) == 0) return i;
    return -1;
}

void permission_create_entry(const char *filename, const char *owner, const char *group) {
    FilePermission entries[MAX_ENTRIES];
    int count = load_entries(entries);

    int idx = find_index(entries, count, filename);
    if (idx == -1) idx = count++;

    strncpy(entries[idx].filename, filename, MAX_FILENAME - 1);
    entries[idx].filename[MAX_FILENAME - 1] = '\0';
    strncpy(entries[idx].owner, owner, 31);
    entries[idx].owner[31] = '\0';
    strncpy(entries[idx].group, group, 15);
    entries[idx].group[15] = '\0';
    strcpy(entries[idx].owner_perm, "rw-");
    strcpy(entries[idx].group_perm, "r--");
    strcpy(entries[idx].others_perm, "---");

    save_entries(entries, count);
}

void permission_remove_entry(const char *filename) {
    FilePermission entries[MAX_ENTRIES];
    int count = load_entries(entries);

    int idx = find_index(entries, count, filename);
    if (idx == -1) return;

    for (int i = idx; i < count - 1; i++) entries[i] = entries[i + 1];
    save_entries(entries, count - 1);
}

static FilePermission *find_entry(FilePermission *entries, int count, const char *filename) {
    int idx = find_index(entries, count, filename);
    return idx == -1 ? NULL : &entries[idx];
}

int permission_check(const char *filename, const char *username,
                      const char *usergroup, char action) {
    FilePermission entries[MAX_ENTRIES];
    int count = load_entries(entries);
    FilePermission *p = find_entry(entries, count, filename);
    if (!p) return 0;   /* no entry -> fail closed, deny by default */

    const char *triad;
    if (strcmp(p->owner, username) == 0)
        triad = p->owner_perm;
    else if (strcmp(p->group, usergroup) == 0)
        triad = p->group_perm;
    else
        triad = p->others_perm;

    return strchr(triad, action) != NULL;
}

void permission_view(const char *filename) {
    FilePermission entries[MAX_ENTRIES];
    int count = load_entries(entries);
    FilePermission *p = find_entry(entries, count, filename);

    if (!p) {
        printf("No permission record found for '%s'.\n", filename);
        return;
    }

    printf("\nFile: %s\n", p->filename);
    printf("Owner : %-10s  Group : %s\n\n", p->owner, p->group);
    printf("Permissions\n");
    printf("  Owner : %s\n", p->owner_perm);
    printf("  Group : %s\n", p->group_perm);
    printf("  Others: %s\n", p->others_perm);
}

static int valid_triad(const char *s) {
    if (strlen(s) != 3) return 0;
    if (s[0] != 'r' && s[0] != '-') return 0;
    if (s[1] != 'w' && s[1] != '-') return 0;
    if (s[2] != 'x' && s[2] != '-') return 0;
    return 1;
}

void permission_set(const char *filename, const char *current_username,
                     const char *current_usergroup) {
    FilePermission entries[MAX_ENTRIES];
    int count = load_entries(entries);
    int idx = find_index(entries, count, filename);

    if (idx == -1) {
        printf("No permission record found for '%s'.\n", filename);
        return;
    }

    int is_owner = strcmp(entries[idx].owner, current_username) == 0;
    int is_admin = strcmp(current_usergroup, "admin") == 0;
    if (!is_owner && !is_admin) {
        printf("Permission Denied. Only the file owner or an admin may change permissions.\n");
        return;
    }

    char buf[16];
    printf("Enter new Owner permission  (e.g. rwx, current: %s): ", entries[idx].owner_perm);
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = '\0';
        if (valid_triad(buf)) strcpy(entries[idx].owner_perm, buf);
        else if (strlen(buf) > 0) printf("  (invalid format, keeping %s)\n", entries[idx].owner_perm);
    }

    printf("Enter new Group permission  (e.g. r--, current: %s): ", entries[idx].group_perm);
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = '\0';
        if (valid_triad(buf)) strcpy(entries[idx].group_perm, buf);
        else if (strlen(buf) > 0) printf("  (invalid format, keeping %s)\n", entries[idx].group_perm);
    }

    printf("Enter new Others permission (e.g. ---, current: %s): ", entries[idx].others_perm);
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = '\0';
        if (valid_triad(buf)) strcpy(entries[idx].others_perm, buf);
        else if (strlen(buf) > 0) printf("  (invalid format, keeping %s)\n", entries[idx].others_perm);
    }

    save_entries(entries, count);
    printf("\nPermissions updated successfully.\n");
}

void permission_set_direct(const char *filename, const char *owner_perm,
                            const char *group_perm, const char *others_perm) {
    FilePermission entries[MAX_ENTRIES];
    int count = load_entries(entries);
    int idx = find_index(entries, count, filename);
    if (idx == -1) return;

    if (valid_triad(owner_perm))  strcpy(entries[idx].owner_perm, owner_perm);
    if (valid_triad(group_perm))  strcpy(entries[idx].group_perm, group_perm);
    if (valid_triad(others_perm)) strcpy(entries[idx].others_perm, others_perm);

    save_entries(entries, count);
}
