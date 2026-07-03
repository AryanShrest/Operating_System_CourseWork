# Task 3 — Secure File Management System (C)

## Project layout
```
SecureFileManager/
├── Makefile
├── README.md
├── config.h          # shared path constants
├── main.c            # menu + program flow
├── auth.c / auth.h            # login system
├── file_ops.c / file_ops.h    # create, read, write, delete
├── permission.c / permission.h# owner/group/others rwx permissions
│

```

## Compile
```
make
```
(equivalent to: `gcc -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE main.c auth.c file_ops.c permission.c -o sfm`)

## Run
```
./sfm
```
On first run the program creates `files/`, `users.txt` (3 sample
accounts), `permissions.txt`, and two sample files (`report.txt`,
`notes.txt`) automatically — nothing needs to be set up by hand.

## Reset the demo data
```
make reset
```
Deletes `users.txt`, `permissions.txt`, and `files/` so the next run
starts from a clean first-run state again.

## Sample accounts (users.txt)
| Username | Password    | Group     |
|----------|-------------|-----------|
| admin    | password123 | admin     |
| john     | hello123    | staff     |
| alice    | abc123      | staff     |

`report.txt` and `notes.txt` are owned by `admin`, group `staff`.

## Menu
```
==============================================
              MAIN MENU
==============================================

1. Create File
2. Read File
3. Write File
4. Delete File
5. File Permissions
6. Logout
0. Exit
```

## Design notes / what each module demonstrates

**auth.c** — login with up to 3 attempts. Passwords are read with
terminal echo disabled (masked, `*` shown per keystroke on a real
terminal; falls back to plain input automatically when stdin isn't a
TTY, e.g. when piping input for testing). Passwords are stored in
**plaintext** in `users.txt` — a deliberate simplification so the file
is easy to inspect for marking. A production system must never do
this: it should store a salted hash (bcrypt/Argon2) and compare
hashes, never the raw password, so that read access to the user
database still doesn't reveal anyone's password.

**file_ops.c** — create / read / write (append) / delete, each gated
by a permission check first.

**permission.c** — a simulated Unix-style owner/group/others `rwx`
system stored in `permissions.txt`, independent of the real
filesystem's permission bits so behaviour is identical on any OS.
Files with no permission record are **denied by default** (fail
closed) rather than allowed. Only the file's owner or a user in the
`admin` group may change a file's permissions (option 5).

## Program flow
```
Start -> init_system() (seed users/files if first run)
      -> Login (auth_login, up to 3 attempts)
      -> Main Menu
           -> Create / Read / Write / Delete   -> permission check
           -> File Permissions                  -> view / (owner or admin) set
           -> Logout  -> back to Login
           -> Exit    -> end program
```
