/*
 * client.c
 *
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 *
 * TCP Chat Client with:
 * - Server authentication
 * - Background receiver thread
 * - Input validation
 * - Interactive messaging
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

/* Read a single newline-terminated line from the socket */
static ssize_t read_line(int fd, char *buffer, size_t max_len)
{
    size_t index = 0;

    while (1)
    {
        char ch;
        ssize_t bytes = recv(fd, &ch, sizeof(ch), 0);

        if (bytes == 0)
        {
            return 0;   // Connection closed
        }

        if (bytes < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }

        if (ch == '\r')
        {
            continue;
        }

        if (ch == '\n')
        {
            buffer[index] = '\0';
            return (ssize_t)index;
        }

        if (index >= max_len - 1)
        {
            return -1;   // Buffer full
        }

        buffer[index++] = ch;
    }
}

/* Send a complete line with newline terminator */
static int send_line(int fd, const char *message)
{
    char buffer[MAX_LINE + 2];
    size_t length, remaining;
    const char *ptr;

    snprintf(buffer, sizeof(buffer), "%s\n", message);

    length = strlen(buffer);
    remaining = length;
    ptr = buffer;

    while (remaining > 0)
    {
        ssize_t bytes = send(fd, ptr, remaining, 0);

        if (bytes == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }

        ptr += bytes;
        remaining -= (size_t)bytes;
    }

    return 0;
}

/* Background thread continuously receives server messages */
static void *reader_thread(void *arg) {
    (void)arg;

    char line[MAX_LINE];

    while (running) {
        ssize_t n = read_line(sock_fd, line, sizeof(line));

        if (n == 0) {
            printf("\n[Connection closed by server]\n");
            running = 0;
            break;
        }

        if (n < 0) {
            if (running)
                printf("\n[Connection error: %s]\n",
                       strerror(errno));

            running = 0;
            break;
        }

        printf("\n<< %s\n> ", line);
        fflush(stdout);
    }

    return NULL;
}

/* Basic client-side input validation */
static int validate_input(const char *s) {
    size_t len = strlen(s);

    if (len == 0 || len >= MAX_LINE - 16)
        return 0;

    return 1;
}

int main(int argc, char *argv[]) {

    const char *server_ip =
        (argc >= 2) ? argv[1] : DEFAULT_IP;

    int port =
        (argc >= 3) ? atoi(argv[2]) : DEFAULT_PORT;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (sock_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip,
                  &server_addr.sin_addr) <= 0) {

        fprintf(stderr,
                "Invalid server address: %s\n",
                server_ip);

        close(sock_fd);
        return EXIT_FAILURE;
    }

    if (connect(sock_fd,
                (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {

        perror("connect");
        close(sock_fd);
        return EXIT_FAILURE;
    }

    printf("Connected to %s:%d\n", server_ip, port);

    char line[MAX_LINE];

    /* Receive welcome message */
    if (read_line(sock_fd, line, sizeof(line)) > 0)
        printf("Server: %s\n", line);

    /* ---------------- Authentication ---------------- */

    char username[64];
    char password[64];

    int authenticated = 0;

    while (!authenticated) {

        printf("Username: ");

        if (!fgets(username, sizeof(username), stdin)) {
            close(sock_fd);
            return EXIT_FAILURE;
        }

        username[strcspn(username, "\n")] = '\0';

        printf("Password: ");

        if (!fgets(password, sizeof(password), stdin)) {
            close(sock_fd);
            return EXIT_FAILURE;
        }

        password[strcspn(password, "\n")] = '\0';

        char auth_cmd[160];

        snprintf(auth_cmd,
                 sizeof(auth_cmd),
                 "AUTH %s %s",
                 username,
                 password);

        if (send_line(sock_fd, auth_cmd) < 0) {
            perror("send");
            close(sock_fd);
            return EXIT_FAILURE;
        }

        ssize_t n =
            read_line(sock_fd, line, sizeof(line));

        if (n <= 0) {
            fprintf(stderr,
                    "Server closed the connection during authentication.\n");
            close(sock_fd);
            return EXIT_FAILURE;
        }

        printf("Server: %s\n", line);

        if (strncmp(line, "OK", 2) == 0) {
            authenticated = 1;
        }
        else if (strstr(line, "429") != NULL) {
            fprintf(stderr,
                    "Too many failed attempts. Disconnecting.\n");
            close(sock_fd);
            return EXIT_FAILURE;
        }
    }

    printf("\nAuthenticated successfully.\n");
    printf("Available Commands:\n");
    printf("  MSG <text>\n");
    printf("  LIST\n");
    printf("  WHOAMI\n");
    printf("  TIME\n");
    printf("  QUIT\n\n");

    /* Start background receiver thread */

    pthread_t tid;

    if (pthread_create(&tid,
                       NULL,
                       reader_thread,
                       NULL) != 0) {

        perror("pthread_create");
        close(sock_fd);
        return EXIT_FAILURE;
    }

    /* ---------------- Main Client Loop ---------------- */

    char input[MAX_LINE];

    while (running) {

        printf("> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
            break;

        input[strcspn(input, "\n")] = '\0';

        if (!validate_input(input)) {
            printf("[Client] Invalid input.\n");
            continue;
        }

        if (send_line(sock_fd, input) < 0) {
            printf("[Client] Send failed: %s\n",
                   strerror(errno));
            break;
        }

        if (strncmp(input, "QUIT", 4) == 0) {
            running = 0;
            break;
        }
    }

    /* ---------------- Cleanup ---------------- */

    running = 0;

    shutdown(sock_fd, SHUT_RDWR);
    close(sock_fd);

    pthread_join(tid, NULL);

    printf("Disconnected.\n");

    return EXIT_SUCCESS;
}