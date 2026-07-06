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