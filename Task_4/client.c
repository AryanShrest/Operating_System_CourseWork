
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "protocol.h"
#include "crypto.h"

#define USE_ENCRYPTION 1   /* set to 0 to send plaintext payloads */

static int g_sock = -1;
static volatile int g_running = 1;

static int send_packet(int fd, Packet *pkt) {
    ssize_t sent = send(fd, pkt, sizeof(Packet), 0);
    if (sent != sizeof(Packet)) {
        perror("send failed");
        return -1;
    }
    return 0;
}

static ssize_t recv_packet(int fd, Packet *pkt) {
    ssize_t total = 0;
    char *buf = (char *)pkt;
    while (total < (ssize_t)sizeof(Packet)) {
        ssize_t n = recv(fd, buf + total, sizeof(Packet) - total, 0);
        if (n <= 0) return n;
        total += n;
    }
    return total;
}

/* Background thread: continuously waits for anything the server
 * sends and prints it immediately. 
 */
static void *receiver_thread(void *arg) {
    (void)arg;
    Packet pkt;

    while (g_running) {
        ssize_t n = recv_packet(g_sock, &pkt);
        if (n <= 0) {
            if (g_running) {
                printf("\n[connection closed by server]\n");
                g_running = 0;
            }
            break;
        }

        if (pkt.type == MSG_DATA) {
            if (pkt.encrypted) {
                xor_crypt(pkt.payload, pkt.length, SESSION_KEY);
            }
            pkt.payload[pkt.length < MAX_PAYLOAD ? pkt.length : MAX_PAYLOAD - 1] = '\0';
            printf("\n[incoming] %s\n> ", pkt.payload);
            fflush(stdout);
        } else if (pkt.type == MSG_ACK) {
            printf("\n[server acknowledged]\n> ");
            fflush(stdout);
        } else if (pkt.type == MSG_ERROR) {
            printf("\n[server rejected message]\n> ");
            fflush(stdout);
        }
        /* other types are ignored on this connection once logged in */
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <server_ip> <port> <username> <password>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *server_ip = argv[1];
    int port = atoi(argv[2]);
    const char *username = argv[3];
    const char *password = argv[4];

    g_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_sock < 0) {
        perror("socket() failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server IP address: %s\n", server_ip);
        close(g_sock);
        return EXIT_FAILURE;
    }

    if (connect(g_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect() failed");
        close(g_sock);
        return EXIT_FAILURE;
    }

    printf("Connected to %s:%d\n", server_ip, port);

    /* --- Step 1: authenticate (this part stays simple request/response) --- */
    Packet login_pkt;
    memset(&login_pkt, 0, sizeof(login_pkt));
    login_pkt.type = MSG_LOGIN;
    login_pkt.encrypted = 0;
    snprintf(login_pkt.payload, MAX_PAYLOAD, "%s:%s", username, password);
    login_pkt.length = (int)strlen(login_pkt.payload);

    if (send_packet(g_sock, &login_pkt) < 0) {
        close(g_sock);
        return EXIT_FAILURE;
    }

    Packet response;
    ssize_t n = recv_packet(g_sock, &response);
    if (n <= 0) {
        fprintf(stderr, "Server closed connection during login\n");
        close(g_sock);
        return EXIT_FAILURE;
    }

    if (response.type == MSG_LOGIN_FAIL) {
        printf("Login failed: invalid username or password.\n");
        close(g_sock);
        return EXIT_FAILURE;
    } else if (response.type != MSG_LOGIN_OK) {
        printf("Unexpected server response during login (type=%d).\n", response.type);
        close(g_sock);
        return EXIT_FAILURE;
    }

    printf("Login successful. Type messages to send (\"quit\" to exit).\n");
    printf("Messages from other logged-in clients will appear as [incoming] ...\n");

    /* --- Step 2: start the background receiver so incoming/relayed
     *             messages can appear at any time, not just right
     *             after we send something. --- */
    pthread_t recv_tid;
    if (pthread_create(&recv_tid, NULL, receiver_thread, NULL) != 0) {
        perror("pthread_create failed");
        close(g_sock);
        return EXIT_FAILURE;
    }

    /* --- Step 3: main thread reads what you type and sends it --- */
    char line[MAX_PAYLOAD];
    while (g_running) {
        printf("> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;
        if (strcmp(line, "quit") == 0) {
            Packet bye = { .type = MSG_DISCONNECT, .length = 0, .encrypted = 0 };
            send_packet(g_sock, &bye);
            break;
        }

        Packet data_pkt;
        memset(&data_pkt, 0, sizeof(data_pkt));
        data_pkt.type = MSG_DATA;
        strncpy(data_pkt.payload, line, MAX_PAYLOAD - 1);
        data_pkt.length = (int)strlen(data_pkt.payload);
        data_pkt.encrypted = USE_ENCRYPTION;

        if (USE_ENCRYPTION) {
            xor_crypt(data_pkt.payload, data_pkt.length, SESSION_KEY);
        }

        if (send_packet(g_sock, &data_pkt) < 0) break;
        /* Reply (ACK/ERROR) and any relayed messages are now printed
         * asynchronously by receiver_thread, not read here. */
    }

    g_running = 0;
    shutdown(g_sock, SHUT_RDWR); /* unblocks the receiver thread's recv() */
    pthread_join(recv_tid, NULL);
    close(g_sock);
    printf("Disconnected.\n");
    return EXIT_SUCCESS;
}
