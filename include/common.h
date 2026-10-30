#ifndef COMMON_H
#define COMMON_H
#include <stddef.h>
#include <stdint.h>
#define MAGIC 0x53554253u
#define VERSION 1
#define MAX_FRAME_SIZE (1u << 20)
enum MsgType {
  AUTH_CHALLENGE = 1,
  AUTH_RESPONSE = 2,
  CIPHER_MAP = 3,
  CIPHERTEXT = 4,
  ACK = 5
};
/* Host-order fields only: wire headers are explicitly encoded, never
 * struct-cast. */
struct MsgHeader {
  uint32_t magic;
  uint16_t version, type;
  uint32_t length;
};
struct SessionStats {
  uint64_t frames, plaintext_bytes, acks;
};
void net_set_timeout_ms(int milliseconds);
int dial_tcp(const char *host, const char *port);
/* 0 success, 1 clean EOF before any bytes, -1 error/partial EOF. */
int read_full(int fd, void *buffer, size_t count);
int write_full(int fd, const void *buffer, size_t count);
int read_frame(int fd, struct MsgHeader *header, uint8_t **body);
int write_frame(int fd, uint16_t type, const uint8_t *body, uint32_t length);
int handle_session(int fd, const char *username, const char *secret);
int handle_session_ex(int fd, const char *username, const char *secret,
                      struct SessionStats *stats);
int apply_subst(const uint8_t map[256], const uint8_t *in, size_t size,
                uint8_t *out);
#endif
