#define _POSIX_C_SOURCE 200809L
#include "common.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int dial_tcp(const char *host, const char *port) {
  struct addrinfo hints = {0}, *res = NULL, *rp = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

  int fd = -1;
  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) continue;
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
    close(fd); fd = -1;
  }
  freeaddrinfo(res);
  return fd; /* -1 if failed */
}

int read_full(int fd, void *buf, size_t n) {
  uint8_t *p = buf;
  size_t got = 0;
  while (got < n) {
    ssize_t r = read(fd, p + got, n - got);
    if (r == 0) return -1;          // EOF
    if (r < 0) { if (errno == EINTR) continue; return -1; }
    got += (size_t)r;
  }
  return 0;
}

int write_full(int fd, const void *buf, size_t n) {
  const uint8_t *p = buf;
  size_t sent = 0;
  while (sent < n) {
    ssize_t w = write(fd, p + sent, n - sent);
    if (w <= 0) { if (errno == EINTR) continue; return -1; }
    sent += (size_t)w;
  }
  return 0;
}

int read_frame(int fd, struct MsgHeader *h, uint8_t **body_out) {
  struct MsgHeader net;
  if (read_full(fd, &net, sizeof(net)) != 0) return -1;

  /* Convert BE → host */
  h->magic   = ntohl(net.magic);
  h->version = ntohs(net.version);
  h->type    = ntohs(net.type);
  h->length  = ntohl(net.length);

  if (h->magic != MAGIC || h->version != VERSION) return -1;
  if (h->length > (1u<<26)) return -1; /* 64 MiB safety */

  if (h->length == 0) { *body_out = NULL; return 0; }
  uint8_t *body = malloc(h->length);
  if (!body) return -1;
  if (read_full(fd, body, h->length) != 0) { free(body); return -1; }
  *body_out = body;
  return 0;
}

int write_frame(int fd, uint16_t type, const uint8_t *body, uint32_t len) {
  struct MsgHeader h = {
    .magic = htonl(MAGIC),
    .version = htons(VERSION),
    .type = htons(type),
    .length = htonl(len)
  };
  if (write_full(fd, &h, sizeof(h)) != 0) return -1;
  if (len && body) {
    if (write_full(fd, body, len) != 0) return -1;
  }
  return 0;
}
