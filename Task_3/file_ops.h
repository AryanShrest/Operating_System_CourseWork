/* file_ops.h - create/read/write/delete operations 
 * operations"). Every operation is gated by permission.c and logged
 * by logger.c.
 */
#ifndef FILE_OPS_H
#define FILE_OPS_H

void file_create(const char *username, const char *usergroup);
void file_read(const char *username, const char *usergroup);
void file_write(const char *username, const char *usergroup);
void file_delete(const char *username, const char *usergroup);

#endif /* FILE_OPS_H */
