/* file_ops.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file_ops.h"
#include "permission.h"
#include "config.h"

static void build_path(char *out, size_t out_size, const char *filename) {
    snprintf(out, out_size, "%s/%s", FILES_DIR, filename);
}

static void read_filename(char *buf, size_t size) {
    printf("Enter filename: ");
    fflush(stdout);
    if (fgets(buf, (int)size, stdin)) buf[strcspn(buf, "\n")] = '\0';
    else buf[0] = '\0';
}

void file_create(const char *username, const char *usergroup) {
    (void)usergroup;
    char filename[MAX_FILENAME], path[MAX_FILENAME + 16];
    read_filename(filename, sizeof(filename));
    build_path(path, sizeof(path), filename);

    FILE *check = fopen(path, "r");
    if (check) {
        fclose(check);
        printf("\nA file with that name already exists.\n");
        return;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        printf("\nCould not create file.\n");
        return;
    }
    fclose(f);

    permission_create_entry(filename, username, usergroup);
    printf("\nFile Created Successfully.\n");
}

void file_read(const char *username, const char *usergroup) {
    char filename[MAX_FILENAME], path[MAX_FILENAME + 16];
    read_filename(filename, sizeof(filename));
    build_path(path, sizeof(path), filename);

    printf("\nChecking Permission...\n");
    if (!permission_check(filename, username, usergroup, 'r')) {
        printf("Permission Denied.\n");
        return;
    }
    printf("Permission Granted.\n\n");

    FILE *f = fopen(path, "r");
    if (!f) {
        printf("File not found.\n");
        return;
    }

    printf("--------------------\n");
    char line[512];
    while (fgets(line, sizeof(line), f)) fputs(line, stdout);
    printf("\n--------------------\n");
    fclose(f);
}

void file_write(const char *username, const char *usergroup) {
    char filename[MAX_FILENAME], path[MAX_FILENAME + 16];
    read_filename(filename, sizeof(filename));
    build_path(path, sizeof(path), filename);

    FILE *check = fopen(path, "r");
    if (!check) {
        printf("\nFile does not exist. Use 'Create File' first.\n");
        return;
    }
    fclose(check);

    printf("\nChecking Permission...\n");
    if (!permission_check(filename, username, usergroup, 'w')) {
        printf("Permission Denied.\n");
        return;
    }
    printf("Permission Granted.\n\n");

    printf("Enter text: ");
    fflush(stdout);
    char text[512];
    if (!fgets(text, sizeof(text), stdin)) text[0] = '\0';
    text[strcspn(text, "\n")] = '\0';

    FILE *f = fopen(path, "a");   /* append mode, as recommended */
    if (!f) {
        printf("\nCould not write to file.\n");
        return;
    }
    fprintf(f, "%s\n", text);
    fclose(f);

    printf("\nSaved Successfully.\n");
}

void file_delete(const char *username, const char *usergroup) {
    char filename[MAX_FILENAME], path[MAX_FILENAME + 16];
    read_filename(filename, sizeof(filename));
    build_path(path, sizeof(path), filename);

    FILE *check = fopen(path, "r");
    if (!check) {
        printf("\nFile not found.\n");
        return;
    }
    fclose(check);

    printf("\nChecking Permission...\n");
    if (!permission_check(filename, username, usergroup, 'w')) {
        printf("Permission Denied.\n");
        return;
    }
    printf("Permission Granted.\n\n");

    printf("Are you sure? (Y/N): ");
    fflush(stdout);
    char confirm[8];
    if (!fgets(confirm, sizeof(confirm), stdin)) confirm[0] = 'n';

    if (confirm[0] == 'Y' || confirm[0] == 'y') {
        remove(path);
        permission_remove_entry(filename);
        printf("\nDeleted Successfully.\n");
    } else {
        printf("\nDeletion cancelled.\n");
    }
}
