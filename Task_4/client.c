/* =====================================================================
 * client_part1.c
 *
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 *
 * Part 1: System headers, configuration macros, and network helper 
 * functions including the background reader thread.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DEFAULT_IP   "127.0.0.1"
#define DEFAULT_PORT 8080
#define MAX_LINE     1024

static int sock_fd = -1;
static volatile int running = 1;

/* Read a single '\n'-terminated line from the socket. Mirrors the
 * server-side implementation so both ends agree on framing. */
static ssize_t read_line(int fd, char *buf, size_t max_len) {
    size_t total = 0;
    while (total < max_len - 1) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0;
        if (c == '\n') {
            buf[total] = '\0';
            return (ssize_t)total;
        }
        if (c != '\r') buf[total++] = c;
    }
    return -1;
}

static int send_line(int fd, const char *msg) {
    char framed[MAX_LINE + 2];
    snprintf(framed, sizeof(framed), "%s\n", msg);
    size_t len = strlen(framed);
    size_t sent_total = 0;
    while (sent_total < len) {
        ssize_t sent = send(fd, framed + sent_total, len - sent_total, 0);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent_total += (size_t)sent;
    }
    return 0;
}

/* Background thread: continuously prints anything the server sends,
 * so broadcast chat messages appear even while the user is typing. */
static void *reader_thread(void *arg) {
    (void)arg;
    char line[MAX_LINE];
    while (running) {
        ssize_t n = read_line(sock_fd, line, sizeof(line));
        if (n == 0) {
            printf("\n[connection closed by server]\n");
            running = 0;
            break;
        }
        if (n < 0) {
            if (running) {
                printf("\n[connection error: %s]\n", strerror(errno));
            }
            running = 0;
            break;
        }
        printf("\n<< %s\n> ", line);
        fflush(stdout);
    }
    return NULL;
}

/* Basic client-side validation before data ever reaches the wire. */
static int validate_input(const char *s) {
    size_t len = strlen(s);
    if (len == 0 || len >= MAX_LINE - 16) return 0;
    return 1;
}

/* =====================================================================
 * client_part2.c
 *
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 *
 * Part 2: Main logic containing TCP setup, interactive authentication loop,
 * thread instantiation, and user input capture.
 */

int main(int argc, char *argv[]) {
    const char *server_ip = argc >= 2 ? argv[1] : DEFAULT_IP;
    int port = argc >= 3 ? atoi(argv[2]) : DEFAULT_PORT;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server address: %s\n", server_ip);
        close(sock_fd);
        return EXIT_FAILURE;
    }

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock_fd);
        return EXIT_FAILURE;
    }

    printf("Connected to %s:%d\n", server_ip, port);

    char line[MAX_LINE];
    /* Read the initial welcome banner */
    if (read_line(sock_fd, line, sizeof(line)) > 0) {
        printf("Server: %s\n", line);
    }

    /* --- Authentication --- */
    char username[64], password[64];
    int authenticated = 0;
    while (!authenticated) {
        printf("Username: ");
        if (!fgets(username, sizeof(username), stdin)) { close(sock_fd); return EXIT_FAILURE; }
        username[strcspn(username, "\n")] = '\0';

        printf("Password: ");
        if (!fgets(password, sizeof(password), stdin)) { close(sock_fd); return EXIT_FAILURE; }
        password[strcspn(password, "\n")] = '\0';

        char auth_cmd[160];
        snprintf(auth_cmd, sizeof(auth_cmd), "AUTH %s %s", username, password);
        if (send_line(sock_fd, auth_cmd) < 0) {
            perror("send");
            close(sock_fd);
            return EXIT_FAILURE;
        }

        ssize_t n = read_line(sock_fd, line, sizeof(line));
        if (n <= 0) {
            fprintf(stderr, "Server closed the connection during authentication.\n");
            close(sock_fd);
            return EXIT_FAILURE;
        }
        printf("Server: %s\n", line);
        if (strncmp(line, "OK", 2) == 0) {
            authenticated = 1;
        } else if (strstr(line, "429") != NULL) {
            fprintf(stderr, "Too many failed attempts. Disconnecting.\n");
            close(sock_fd);
            return EXIT_FAILURE;
        }
        /* otherwise loop and retry */
    }

    printf("Authenticated. Commands: MSG <text> | LIST | WHOAMI | TIME | QUIT\n");

    pthread_t tid;
    pthread_create(&tid, NULL, reader_thread, NULL);

    char input[MAX_LINE];
    while (running) {
        printf("> ");
        fflush(stdout);
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';

        if (!validate_input(input)) {
            printf("[client] Input rejected: empty or too long.\n");
            continue;
        }

        if (send_line(sock_fd, input) < 0) {
            printf("[client] Failed to send: %s\n", strerror(errno));
            break;
        }

        if (strncmp(input, "QUIT", 4) == 0) {
            running = 0;
            break;
        }
    }

    running = 0;
    shutdown(sock_fd, SHUT_RDWR);
    close(sock_fd);
    pthread_join(tid, NULL);

    printf("Disconnected.\n");
    return EXIT_SUCCESS;
}