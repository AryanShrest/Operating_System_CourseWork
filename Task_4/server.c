/* =====================================================================
 * server.c
 *
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 *
 * Multi-threaded TCP server demonstrating:
 * - Socket-based inter-process communication
 * - A simple line-based text protocol (see PROTOCOL.md)
 * - Concurrent client handling using POSIX threads (one thread/client)
 * - Username/password authentication using crypt() password hashing
 * - Basic input validation and sanitisation
 * - Robust error handling and clean resource management
 *
 * Compile:
 * gcc -Wall -o server server.c -lpthread -lcrypt
 *
 * Run:
 * ./server [port]        (default port 8080)
 * =====================================================================
 */

#define _GNU_SOURCE
#include <stddef.h> /* Defines size_t safely before string.h and unistd.h */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <pthread.h>
#include <crypt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* ---------------------------------------------------------------------
 * Configuration constants
 * ------------------------------------------------------------------- */
#define DEFAULT_PORT     8080
#define MAX_CLIENTS      20
#define MAX_LINE         1024
#define MAX_USERNAME     32
#define MAX_PASSWORD     64
#define MAX_HASH         128
#define MAX_USERS        8
#define LISTEN_BACKLOG   16

/* ---------------------------------------------------------------------
 * Data structures
 * ------------------------------------------------------------------- */

/* A registered user account. Passwords are never stored in plain text;
 * they are hashed with crypt() (SHA-512, glibc extension) at startup. */
typedef struct {
    char username[MAX_USERNAME];
    char hash[MAX_HASH];
} user_account_t;

/* Represents one connected client, authenticated or not. */
typedef struct {
    int  socket_fd;
    struct sockaddr_in address;
    int  authenticated;
    char username[MAX_USERNAME];
    int  in_use;                 /* slot occupied flag */
} client_t;

static user_account_t user_db[MAX_USERS];
static int user_count = 0;

static client_t clients[MAX_CLIENTS];
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex     = PTHREAD_MUTEX_INITIALIZER;

static volatile sig_atomic_t server_running = 1;

/* ---------------------------------------------------------------------
 * Utility: thread-safe timestamped logging (audit trail)
 * ------------------------------------------------------------------- */
static void log_event(const char *fmt, ...) {
    char timebuf[32];
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_now);

    pthread_mutex_lock(&log_mutex);
    printf("[%s] ", timebuf);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
    pthread_mutex_unlock(&log_mutex);
}

/* ---------------------------------------------------------------------
 * User database initialisation (demo accounts).
 * In a production system this would be loaded from a secured file
 * or external identity provider, never hard-coded.
 * ------------------------------------------------------------------- */
static void init_users(void) {
    struct { const char *user; const char *pass; } demo[] = {
        {"alice", "alice123"},
        {"bob",   "bob123"},
        {"admin", "admin123"}
    };
    const char *salt = "$6$st5004salt$"; /* SHA-512 crypt salt */

    for (size_t i = 0; i < sizeof(demo) / sizeof(demo[0]) && user_count < MAX_USERS; i++) {
        strncpy(user_db[user_count].username, demo[i].user, MAX_USERNAME - 1);
        user_db[user_count].username[MAX_USERNAME - 1] = '\0'; /* Ensure null-termination */
        
        char *hashed = crypt(demo[i].pass, salt);
        if (!hashed) {
            log_event("FATAL: crypt() failed while initialising users");
            exit(EXIT_FAILURE);
        }
        strncpy(user_db[user_count].hash, hashed, MAX_HASH - 1);
        user_db[user_count].hash[MAX_HASH - 1] = '\0'; /* Ensure null-termination */
        user_count++;
    }
    log_event("Initialised %d demo user accounts", user_count);
}

/* Verify username/password against the user database. Returns 1 on
 * success, 0 on failure. Never leaks whether the username exists via
 * timing differences beyond what crypt() itself introduces. */
static int authenticate(const char *username, const char *password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(user_db[i].username, username) == 0) {
            char *result = crypt(password, user_db[i].hash);
            return (result && strcmp(result, user_db[i].hash) == 0) ? 1 : 0;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * Input validation - a core security measure for Task 4.
 * Rejects overly long input, embedded NUL bytes, and other control
 * characters that could be used to break the line protocol.
 * ------------------------------------------------------------------- */
static int validate_line(const char *buf, size_t len) {
    if (len == 0 || len >= MAX_LINE) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == '\0') return 0;
        if (iscntrl(c) && c != '\n' && c != '\r') return 0;
    }
    return 1;
}

/* ---------------------------------------------------------------------
 * Client slot management (shared state protected by clients_mutex)
 * ------------------------------------------------------------------- */
static int register_client_slot(int fd, struct sockaddr_in addr) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].in_use) {
            clients[i].in_use = 1;
            clients[i].socket_fd = fd;
            clients[i].address = addr;
            clients[i].authenticated = 0;
            clients[i].username[0] = '\0';
            pthread_mutex_unlock(&clients_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return -1; /* server full */
}

static void release_client_slot(int index) {
    pthread_mutex_lock(&clients_mutex);
    if (index >= 0 && index < MAX_CLIENTS) {
        close(clients[index].socket_fd);
        clients[index].in_use = 0;
        clients[index].authenticated = 0;
    }
    pthread_mutex_unlock(&clients_mutex);
}

/* Broadcast a chat message to every authenticated client. */
static void broadcast_message(int sender_index, const char *username, const char *text) {
    char outgoing[MAX_LINE];
    snprintf(outgoing, sizeof(outgoing), "MSG %s: %s\n", username, text);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].in_use && clients[i].authenticated && i != sender_index) {
            ssize_t sent = send(clients[i].socket_fd, outgoing, strlen(outgoing), MSG_NOSIGNAL);
            if (sent < 0) {
                log_event("WARN: failed to deliver message to client slot %d (%s)", i, strerror(errno));
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

/* List currently authenticated usernames into a buffer. */
static void list_users(char *out, size_t out_size) {
    pthread_mutex_lock(&clients_mutex);
    size_t used = 0;
    int n;

    n = snprintf(out + used, out_size - used, "OK ");
    if (n > 0 && (size_t)n < out_size - used) {
        used += n;
    }

    int first = 1;
    for (int i = 0; i < MAX_CLIENTS && used < out_size - 1; i++) {
        if (clients[i].in_use && clients[i].authenticated) {
            n = snprintf(out + used, out_size - used, "%s%s", first ? "" : ",", clients[i].username);
            if (n > 0 && (size_t)n < out_size - used) {
                used += n;
            }
            first = 0;
        }
    }
    if (first) {
        n = snprintf(out + used, out_size - used, "(none)");
        if (n > 0 && (size_t)n < out_size - used) {
            used += n;
        }
    }
    
    snprintf(out + used, out_size - used, "\n");
    pthread_mutex_unlock(&clients_mutex);
}

/* ---------------------------------------------------------------------
 * Networking helper: read a single '\n'-terminated line from a socket.
 * Returns the number of bytes read (excluding the newline), 0 if the
 * peer closed the connection, or -1 on error / line-too-long.
 * ------------------------------------------------------------------- */
static ssize_t read_line(int fd, char *buf, size_t max_len) {
    size_t total = 0;
    while (total < max_len - 1) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0; /* connection closed */
        if (c == '\n') {
            buf[total] = '\0';
            return (ssize_t)total;
        }
        if (c != '\r') buf[total++] = c;
    }
    return -1; /* line too long - protocol violation */
}

static void send_line(int fd, const char *msg) {
    ssize_t len = (ssize_t)strlen(msg);
    ssize_t sent_total = 0;
    while (sent_total < len) {
        ssize_t sent = send(fd, msg + sent_total, len - sent_total, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return; /* client likely disconnected; caller will detect on next recv */
        }
        sent_total += sent;
    }
}

/* ---------------------------------------------------------------------
 * Per-client worker thread
 * ------------------------------------------------------------------- */
typedef struct {
    int fd;
    struct sockaddr_in addr;
} conn_args_t;

static void *handle_client(void *arg) {
    conn_args_t *cargs = (conn_args_t *)arg;
    int fd = cargs->fd;
    struct sockaddr_in addr = cargs->addr;
    free(cargs);

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));

    int slot = register_client_slot(fd, addr);
    if (slot < 0) {
        send_line(fd, "ERR 503 server_full\n");
        log_event("Rejected connection from %s: server full", ip);
        close(fd);
        return NULL;
    }

    log_event("Client connected from %s:%d (slot %d)", ip, ntohs(addr.sin_port), slot);
    send_line(fd, "OK welcome ST5004CEM-chat-server AUTH_REQUIRED\n");

    char line[MAX_LINE];
    int attempts = 0;
    const int MAX_AUTH_ATTEMPTS = 3;

    for (;;) {
        ssize_t n = read_line(fd, line, sizeof(line));
        if (n == 0) {
            log_event("Client %s disconnected (slot %d)", ip, slot);
            break;
        }
        if (n < 0) {
            log_event("Connection error from %s (slot %d): %s", ip, slot, strerror(errno));
            break;
        }
        if (!validate_line(line, (size_t)n)) {
            send_line(fd, "ERR 400 invalid_input\n");
            continue;
        }

        char cmd[16] = {0};
        char rest[MAX_LINE] = {0};
        sscanf(line, "%15s %[^\n]", cmd, rest);

        if (strcmp(cmd, "AUTH") == 0) {
            char user[MAX_USERNAME] = {0}, pass[MAX_PASSWORD] = {0};
            if (sscanf(rest, "%31s %63s", user, pass) != 2) {
                send_line(fd, "ERR 400 usage_AUTH_user_pass\n");
                continue;
            }
            if (authenticate(user, pass)) {
                pthread_mutex_lock(&clients_mutex);
                clients[slot].authenticated = 1;
                strncpy(clients[slot].username, user, MAX_USERNAME - 1);
                clients[slot].username[MAX_USERNAME - 1] = '\0'; /* Ensure null-termination */
                pthread_mutex_unlock(&clients_mutex);
                send_line(fd, "OK authenticated\n");
                log_event("User '%s' authenticated from %s (slot %d)", user, ip, slot);
            } else {
                attempts++;
                send_line(fd, "ERR 401 authentication_failed\n");
                log_event("SECURITY: failed login attempt for '%s' from %s", user, ip);
                if (attempts >= MAX_AUTH_ATTEMPTS) {
                    send_line(fd, "ERR 429 too_many_attempts_closing\n");
                    log_event("SECURITY: closing connection from %s after %d failed attempts", ip, attempts);
                    break;
                }
            }
            continue;
        }

        /* All commands below this point require authentication */
        if (!clients[slot].authenticated) {
            send_line(fd, "ERR 403 authentication_required\n");
            continue;
        }

        if (strcmp(cmd, "MSG") == 0) {
            if (strlen(rest) == 0) {
                send_line(fd, "ERR 400 empty_message\n");
                continue;
            }
            broadcast_message(slot, clients[slot].username, rest);
            send_line(fd, "OK message_sent\n");
            log_event("MSG from %s: %s", clients[slot].username, rest);
        } else if (strcmp(cmd, "LIST") == 0) {
            char resp[MAX_LINE];
            list_users(resp, sizeof(resp));
            send_line(fd, resp);
        } else if (strcmp(cmd, "WHOAMI") == 0) {
            char resp[MAX_LINE];
            snprintf(resp, sizeof(resp), "OK %s\n", clients[slot].username);
            send_line(fd, resp);
        } else if (strcmp(cmd, "TIME") == 0) {
            char resp[MAX_LINE];
            time_t now = time(NULL);
            struct tm tm_now;
            localtime_r(&now, &tm_now);
            char tbuf[64];
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm_now);
            snprintf(resp, sizeof(resp), "OK %s\n", tbuf);
            send_line(fd, resp);
        } else if (strcmp(cmd, "QUIT") == 0) {
            send_line(fd, "OK bye\n");
            log_event("User '%s' quit (slot %d)", clients[slot].username, slot);
            break;
        } else {
            send_line(fd, "ERR 400 unknown_command\n");
        }
    }

    release_client_slot(slot);
    return NULL;
}

/* ---------------------------------------------------------------------
 * Graceful shutdown on SIGINT/SIGTERM
 * ------------------------------------------------------------------- */
static void handle_signal(int sig) {
    (void)sig;
    server_running = 0;
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    if (argc >= 2) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port: %s\n", argv[1]);
            return EXIT_FAILURE;
        }
    }

    signal(SIGPIPE, SIG_IGN); /* prevent crash if a client disconnects mid-send */
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    init_users();
    memset(clients, 0, sizeof(clients));

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return EXIT_FAILURE;
    }

    if (listen(server_fd, LISTEN_BACKLOG) < 0) {
        perror("listen");
        close(server_fd);
        return EXIT_FAILURE;
    }

    log_event("Server listening on port %d (max %d concurrent clients)", port, MAX_CLIENTS);

    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue; /* interrupted by signal, check server_running */
            perror("accept");
            continue;
        }

        conn_args_t *cargs = malloc(sizeof(conn_args_t));
        if (!cargs) {
            log_event("ERROR: out of memory handling new connection");
            close(client_fd);
            continue;
        }
        cargs->fd = client_fd;
        cargs->addr = client_addr;

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, cargs) != 0) {
            log_event("ERROR: failed to create thread for new client");
            free(cargs);
            close(client_fd);
            continue;
        }
        pthread_detach(tid); /* thread cleans up its own resources on exit */
    }

    log_event("Server shutting down");
    close(server_fd);
    return EXIT_SUCCESS;
}