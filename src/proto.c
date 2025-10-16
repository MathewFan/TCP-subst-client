#define _POSIX_C_SOURCE 200809L
#include "common.h"
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* hex-encode helper */
static void to_hex(const uint8_t *in, size_t n, char *out_hex) {
  static const char *d = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out_hex[2*i]   = d[(in[i] >> 4) & 0xF];
    out_hex[2*i+1] = d[in[i] & 0xF];
  }
  out_hex[2*n] = '\0';
}

int handle_session(int fd, const char *username, const char *secret) {
  uint8_t subst_map[256] = {0};
  int have_map = 0;

  while (1) {
    struct MsgHeader h; uint8_t *body = NULL;
    if (read_frame(fd, &h, &body) != 0) return 0;

    switch (h.type) {
      case AUTH_CHALLENGE: {
        /* body = salt string */
        const char *salt = (const char*)body;
        size_t payload_len = h.length;

        /* Build message username|salt|secret */
        size_t ulen = strlen(username), slen = payload_len, klen = strlen(secret);
        size_t msg_len = ulen + 1 + slen + 1 + klen;
        char *msg = malloc(msg_len + 1);
        if (!msg) { free(body); return -1; }
        snprintf(msg, msg_len + 1, "%s|%.*s|%s", username, (int)slen, salt, secret);

        unsigned int outlen = 0;
        unsigned char mac[EVP_MAX_MD_SIZE];
        HMAC(EVP_sha256(), secret, (int)klen, (unsigned char*)msg, (int)strlen(msg), mac, &outlen);

        char hex[2*EVP_MAX_MD_SIZE + 1];
        to_hex(mac, outlen, hex);

        if (write_frame(fd, AUTH_RESPONSE, (uint8_t*)hex, (uint32_t)strlen(hex)) != 0) {
          free(msg); free(body); return -1;
        }
        free(msg); free(body);
        break;
      }
      case CIPHER_MAP: {
        if (h.length != 256) { free(body); return -1; }
        memcpy(subst_map, body, 256);
        have_map = 1;
        free(body);
        break;
      }
      case CIPHERTEXT: {
        if (!have_map) { free(body); return -1; }
        uint8_t *plain = malloc(h.length);
        if (!plain) { free(body); return -1; }
        apply_subst(subst_map, body, h.length, plain);

        /* Print plaintext to stdout (binary-safe write) */
        if (write_full(STDOUT_FILENO, plain, h.length) != 0) {
          free(plain); free(body); return -1;
        }
        /* Acknowledge */
        (void)write_frame(fd, ACK, NULL, 0);

        free(plain); free(body);
        break;
      }
      case ACK:
        /* Ignore (server acks us) */
        free(body);
        break;
      default:
        free(body);
        return -1;
    }
  }
}
