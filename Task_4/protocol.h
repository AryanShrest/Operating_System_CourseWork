#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

/* ---------------------------------------------------------------------
 * Simple Application Layer Protocol (SALP)
 * -----------------------------------------------------------------
 * Every message exchanged between client and server uses a fixed
 * size Packet struct. This keeps parsing simple (no need to hunt
 * for delimiters) at the cost of a little wasted space. The
 * "length" field tells the receiver how many bytes of "payload"
 * are actually meaningful.
 * --------------------------------------------------------------- */

#define MAX_PAYLOAD   1024
#define MAX_USERNAME  32
#define MAX_PASSWORD  32

/* Message types exchanged between client and server */
typedef enum {
    MSG_LOGIN        = 1,  /* client -> server : "username:password" */
    MSG_LOGIN_OK     = 2,  /* server -> client : authentication succeeded */
    MSG_LOGIN_FAIL   = 3,  /* server -> client : authentication failed */
    MSG_DATA         = 4,  /* client -> server : application data */
    MSG_ACK          = 5,  /* server -> client : data received OK */
    MSG_ERROR        = 6,  /* server -> client : malformed / invalid request */
    MSG_DISCONNECT   = 7   /* client -> server : client is closing the session */
} MsgType;

/* Wire format of every message.
 * encrypted flag tells the receiver whether payload has been
 * XOR-encrypted with the shared session key (see crypto.h). */
typedef struct {
    int32_t type;               /* one of MsgType            */
    int32_t length;             /* number of valid bytes in payload */
    int32_t encrypted;          /* 1 = payload is encrypted, 0 = plain */
    char    payload[MAX_PAYLOAD];
} Packet;

#endif /* PROTOCOL_H */
