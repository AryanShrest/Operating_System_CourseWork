/* ---------------------------------------------------------------------
 * server.c - Multi-threaded TCP server (Task 4: Network Programming & IPC)
 *
 * Features:
 *   - One thread per connected client (pthreads)
 *   - Fixed-size packet protocol (see protocol.h)
 *   - Username/password authentication (see auth.h)
 *   - Payload validation (length bounds, type checks)
 *   - Optional XOR encryption of payload (see crypto.h)
 *   - Thread-safe active-client tracking with a mutex
 *   - Audit-style logging of connects/disconnects/auth attempts
 * --------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "protocol.h"
#include "auth.h"
#include "crypto.h"

#define PORT            8080
#define BACKLOG         10
#define MAX_CLIENTS     50

/* ---- shared state protected by g_clients_mutex -------------------- */
static int  g_active_clients = 0;
static pthread_mutex_t g_clients_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Registry of currently logged-in clients, used to relay ("broadcast")
 * chat messages from one client to every other connected client.
 * Protected by the same g_clients_mutex as the active-client count. */
typedef struct {
    int  fd;
    char username[MAX_USERNAME];
    int  in_use;
} ClientSlot;

static ClientSlot g_clients[MAX_CLIENTS];
/* --------------------------------------------------------------------*/

typedef struct {
    int  fd;
    struct sockaddr_in addr;
} ClientCtx;

/* Adds a logged-in client to the registry so it can receive relayed
 * messages from other clients. Returns 1 on success, 0 if the
 * registry is full. */
static int register_client(int fd, const char *username) {
    int ok = 0;
    pthread_mutex_lock(&g_clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_clients[i].in_use) {
            g_clients[i].fd = fd;
            strncpy(g_clients[i].username, username, MAX_USERNAME - 1);
            g_clients[i].in_use = 1;
            ok = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_clients_mutex);
    return ok;
}

/* Removes a client from the registry (called on disconnect). */
static void unregister_client(int fd) {
    pthread_mutex_lock(&g_clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].in_use && g_clients[i].fd == fd) {
            g_clients[i].in_use = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_clients_mutex);
}

/* Simple timestamped logger used for the "audit log" requirement. */
static void log_event(const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    va_list args;
    va_start(args, fmt);
    printf("[%s] ", timebuf);
    vprintf(fmt, args);
    printf("\n");
    fflush(stdout);
    va_end(args);
}

/* Sends a packet, returns 0 on success, -1 on error. */
static int send_packet(int fd, Packet *pkt) {
    ssize_t sent = send(fd, pkt, sizeof(Packet), 0);
    if (sent != sizeof(Packet)) {
        perror("send failed");
        return -1;
    }
    return 0;
}

/* Receives a packet, returns bytes read (0 = orderly shutdown, <0 = error). */
static ssize_t recv_packet(int fd, Packet *pkt) {
    ssize_t total = 0;
    char *buf = (char *)pkt;
    while (total < (ssize_t)sizeof(Packet)) {
        ssize_t n = recv(fd, buf + total, sizeof(Packet) - total, 0);
        if (n <= 0) return n; /* 0 = closed, <0 = error */
        total += n;
    }
    return total;
}

/* Validates an incoming packet before it is trusted / processed. */
static int packet_is_valid(const Packet *pkt) {
    if (pkt->length < 0 || pkt->length >= MAX_PAYLOAD) return 0;
    if (pkt->type < MSG_LOGIN || pkt->type > MSG_DISCONNECT) return 0;
    return 1;
}

/* Relays a chat message from `sender_username` to every other
 * currently logged-in client (all fds in g_clients except sender_fd).
 * This is what lets two clients "talk" to each other through the
 * server. The relayed message is sent as plaintext MSG_DATA prefixed
 * with the sender's username, e.g. "alice: hello". */
static void broadcast_message(int sender_fd, const char *sender_username, const char *text) {
    Packet out;
    memset(&out, 0, sizeof(out));
    out.type = MSG_DATA;
    out.encrypted = 0;
    snprintf(out.payload, MAX_PAYLOAD, "%s: %s", sender_username, text);
    out.length = (int)strlen(out.payload);

    pthread_mutex_lock(&g_clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].in_use && g_clients[i].fd != sender_fd) {
            send_packet(g_clients[i].fd, &out); /* best-effort; ignore individual send failures */
        }
    }
    pthread_mutex_unlock(&g_clients_mutex);
}

static void *handle_client(void *arg) {
    ClientCtx *ctx = (ClientCtx *)arg;
    int fd = ctx->fd;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ctx->addr.sin_addr, ip, sizeof(ip));
    int port = ntohs(ctx->addr.sin_port);
    free(ctx);

    pthread_mutex_lock(&g_clients_mutex);
    g_active_clients++;
    int active_now = g_active_clients;
    pthread_mutex_unlock(&g_clients_mutex);

    log_event("Client connected from %s:%d (active clients: %d)", ip, port, active_now);

    Packet pkt;
    char authenticated_user[MAX_USERNAME] = {0};
    int is_authenticated = 0;

    /* --- Step 1: require authentication before anything else --- */
    ssize_t n = recv_packet(fd, &pkt);
    if (n <= 0) {
        log_event("Client %s:%d disconnected before login", ip, port);
        goto cleanup;
    }

    if (!packet_is_valid(&pkt) || pkt.type != MSG_LOGIN) {
        log_event("Rejected malformed/unexpected first packet from %s:%d", ip, port);
        Packet err = { .type = MSG_ERROR, .length = 0, .encrypted = 0 };
        send_packet(fd, &err);
        goto cleanup;
    }

    {
        /* payload format expected: "username:password" */
        pkt.payload[pkt.length < MAX_PAYLOAD ? pkt.length : MAX_PAYLOAD - 1] = '\0';
        char *sep = strchr(pkt.payload, ':');
        if (!sep) {
            log_event("Malformed login payload from %s:%d", ip, port);
            Packet fail = { .type = MSG_LOGIN_FAIL, .length = 0, .encrypted = 0 };
            send_packet(fd, &fail);
            goto cleanup;
        }
        *sep = '\0';
        const char *user = pkt.payload;
        const char *pass = sep + 1;

        if (authenticate(user, pass)) {
            is_authenticated = 1;
            strncpy(authenticated_user, user, MAX_USERNAME - 1);
            log_event("AUTH SUCCESS: user '%s' from %s:%d", user, ip, port);
            Packet ok = { .type = MSG_LOGIN_OK, .length = 0, .encrypted = 0 };
            send_packet(fd, &ok);

            if (!register_client(fd, authenticated_user)) {
                log_event("Client registry full - '%s' cannot receive relayed messages", authenticated_user);
            }
        } else {
            log_event("AUTH FAILURE: user '%s' from %s:%d", user, ip, port);
            Packet fail = { .type = MSG_LOGIN_FAIL, .length = 0, .encrypted = 0 };
            send_packet(fd, &fail);
            goto cleanup;
        }
    }

    /* --- Step 2: main message loop (only reached if authenticated) --- */
    while (is_authenticated && (n = recv_packet(fd, &pkt)) > 0) {
        if (!packet_is_valid(&pkt)) {
            log_event("Rejected invalid packet from user '%s'", authenticated_user);
            Packet err = { .type = MSG_ERROR, .length = 0, .encrypted = 0 };
            send_packet(fd, &err);
            continue;
        }

        if (pkt.type == MSG_DISCONNECT) {
            log_event("User '%s' requested disconnect", authenticated_user);
            break;
        }

        if (pkt.type == MSG_DATA) {
            if (pkt.encrypted) {
                xor_crypt(pkt.payload, pkt.length, SESSION_KEY);
            }
            pkt.payload[pkt.length < MAX_PAYLOAD ? pkt.length : MAX_PAYLOAD - 1] = '\0';
            log_event("DATA from '%s': %s", authenticated_user, pkt.payload);

            Packet ack = { .type = MSG_ACK, .length = 0, .encrypted = 0 };
            send_packet(fd, &ack);
            log_event("Sent ACK to '%s'", authenticated_user);

            /* Relay this message to every other connected client so
             * clients can message each other through the server. */
            broadcast_message(fd, authenticated_user, pkt.payload);
            log_event("Relayed message from '%s' to other connected clients", authenticated_user);
        } else {
            log_event("Unexpected message type %d from '%s'", pkt.type, authenticated_user);
            Packet err = { .type = MSG_ERROR, .length = 0, .encrypted = 0 };
            send_packet(fd, &err);
        }
    }

    if (n < 0) {
        perror("recv error");
    }

cleanup:
    close(fd);
    unregister_client(fd);
    pthread_mutex_lock(&g_clients_mutex);
    g_active_clients--;
    int remaining = g_active_clients;
    pthread_mutex_unlock(&g_clients_mutex);
    log_event("Connection closed for %s:%d (active clients: %d)", ip, port, remaining);
    return NULL;
}

int main(void) {
    auth_init();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt() failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen() failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_event("Server listening on port %d", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept() failed");
            continue;
        }

        pthread_mutex_lock(&g_clients_mutex);
        int would_exceed = (g_active_clients >= MAX_CLIENTS);
        pthread_mutex_unlock(&g_clients_mutex);

        if (would_exceed) {
            log_event("Connection refused: server at capacity (%d clients)", MAX_CLIENTS);
            Packet err = { .type = MSG_ERROR, .length = 0, .encrypted = 0 };
            send_packet(client_fd, &err);
            close(client_fd);
            continue;
        }

        ClientCtx *ctx = malloc(sizeof(ClientCtx));
        if (!ctx) {
            perror("malloc failed");
            close(client_fd);
            continue;
        }
        ctx->fd = client_fd;
        ctx->addr = client_addr;

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, ctx) != 0) {
            perror("pthread_create failed");
            free(ctx);
            close(client_fd);
            continue;
        }
        pthread_detach(tid);
    }

    close(server_fd);
    return 0;
}
