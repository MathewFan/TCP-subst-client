#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

#define MAGIC 0x53554253u /* "SUBS" */
#define VERSION 1

enum MsgType {
  AUTH_CHALLENGE = 1,
  AUTH_RESPONSE  = 2,
  CIPHER_MAP     = 3,
  CIPHERTEXT     = 4,
  ACK            = 5
};

struct MsgHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t type;
  uint32_t length;
} __attribute__((packed));

/* net.c */
int dial_tcp(const char *host, const char *port);
int read_full(int fd, void *buf, size_t n);     /* handles short reads */
int write_full(int fd, const void *buf, size_t n);
int read_frame(int fd, struct MsgHeader *h, uint8_t **body_out);
int write_frame(int fd, uint16_t type, const uint8_t *body, uint32_t len);

/* proto.c */
int handle_session(int fd, const char *username, const char *secret);

/* cipher.c */
int apply_subst(const uint8_t map[256], const uint8_t *in, size_t n, uint8_t *out);

#endif
