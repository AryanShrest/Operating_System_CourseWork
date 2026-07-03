/* config.h - shared path constants used by every module.
 * Centralising these avoids magic strings scattered across files and
 * makes it trivial to relocate the "data directory" if needed.
 */
#ifndef CONFIG_H
#define CONFIG_H

#define USERS_FILE       "users.txt"
#define PERMISSIONS_FILE "permissions.txt"
#define AUDIT_LOG_FILE   "audit.log"
#define FILES_DIR        "files"

#define UI_LINE "=============================================="

#endif /* CONFIG_H */
