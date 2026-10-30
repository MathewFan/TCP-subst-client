#define _POSIX_C_SOURCE 200809L
#include "common.h"
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int authenticate(int fd, const char *username, const char *secret,
                        const uint8_t *salt, size_t length) {
  size_t user_length = strlen(username), key_length = strlen(secret),
         size = user_length + length + key_length + 2;
  if (!user_length || user_length > 255 || !key_length || key_length > 4096) {
    errno = EINVAL;
    return -1;
  }
  uint8_t *message = malloc(size);
  if (!message)
    return -1;
  memcpy(message, username, user_length);
  message[user_length] = '|';
  memcpy(message + user_length + 1, salt, length);
  message[user_length + 1 + length] = '|';
  memcpy(message + user_length + length + 2, secret, key_length);
  uint8_t mac[EVP_MAX_MD_SIZE];
  unsigned int mac_length = 0;
  unsigned char *ok = HMAC(EVP_sha256(), secret, (int)key_length, message, size,
                           mac, &mac_length);
  OPENSSL_cleanse(message, size);
  free(message);
  if (!ok || mac_length != 32)
    return -1;
  static const char digits[] = "0123456789abcdef";
  uint8_t hex[64];
  for (size_t i = 0; i < 32; i++) {
    hex[2 * i] = digits[mac[i] >> 4];
    hex[2 * i + 1] = digits[mac[i] & 15];
  }
  int result = write_frame(fd, AUTH_RESPONSE, hex, sizeof(hex));
  OPENSSL_cleanse(mac, sizeof(mac));
  OPENSSL_cleanse(hex, sizeof(hex));
  return result;
}
int handle_session_ex(int fd, const char *username, const char *secret,
                      struct SessionStats *stats) {
  enum { CHALLENGE, MAP, STREAM } state = CHALLENGE;
  uint8_t map[256];
  for (;;) {
    struct MsgHeader header;
    uint8_t *body = NULL;
    int rc = read_frame(fd, &header, &body);
    if (rc == 1) {
      if (state == STREAM)
        return 0;
      errno = EPROTO;
      return -1;
    }
    if (rc < 0)
      return -1;
    if (stats)
      stats->frames++;
    if (state == CHALLENGE && header.type == AUTH_CHALLENGE) {
      rc = authenticate(fd, username, secret, body, header.length);
      if (!rc)
        state = MAP;
    } else if (state == MAP && header.type == CIPHER_MAP) {
      uint8_t seen[256] = {0};
      rc = 0;
      for (size_t i = 0; i < 256; i++)
        if (seen[body[i]]++) {
          rc = -1;
          break;
        }
      if (!rc) {
        memcpy(map, body, 256);
        state = STREAM;
      }
    } else if (state == STREAM && header.type == CIPHERTEXT) {
      apply_subst(map, body, header.length, body);
      rc = write_full(STDOUT_FILENO, body, header.length);
      if (!rc)
        rc = write_frame(fd, ACK, NULL, 0);
      if (!rc && stats) {
        stats->plaintext_bytes += header.length;
        stats->acks++;
      }
    } else if (state == STREAM && header.type == ACK && header.length == 0)
      rc = 0;
    else
      rc = -1;
    free(body);
    if (rc) {
      errno = EPROTO;
      return -1;
    }
  }
}
int handle_session(int fd, const char *username, const char *secret) {
  return handle_session_ex(fd, username, secret, NULL);
}
