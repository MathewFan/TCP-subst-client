#define _POSIX_C_SOURCE 200809L
#include "common.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static int timeout_ms = 5000;
void net_set_timeout_ms(int value) { timeout_ms = value; }
static int64_t clock_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
    return -1;
  return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int ready(int fd, short events, int64_t deadline) {
  for (;;) {
    int64_t left = deadline - clock_ms();
    if (left <= 0) {
      errno = ETIMEDOUT;
      return -1;
    }
    struct pollfd poller = {fd, events, 0};
    int result = poll(&poller, 1, (int)(left > INT_MAX ? INT_MAX : left));
    if (result < 0 && errno == EINTR)
      continue;
    if (result == 0) {
      errno = ETIMEDOUT;
      return -1;
    }
    if (result < 0)
      return -1;
    if (poller.revents & POLLNVAL) {
      errno = EBADF;
      return -1;
    }
    return 0;
  }
}
static int transfer(int fd, void *buffer, size_t count, int writing,
                    int64_t deadline) {
  uint8_t *bytes = buffer;
  size_t offset = 0;
  while (offset < count) {
    if (ready(fd, writing ? POLLOUT : POLLIN, deadline) < 0)
      return -1;
    ssize_t n = writing ? write(fd, bytes + offset, count - offset)
                        : read(fd, bytes + offset, count - offset);
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
      continue;
    if (n < 0)
      return -1;
    if (n == 0) {
      if (!writing && !offset)
        return 1;
      errno = EPROTO;
      return -1;
    }
    offset += (size_t)n;
  }
  return 0;
}
int read_full(int fd, void *buffer, size_t count) {
  return transfer(fd, buffer, count, 0, clock_ms() + timeout_ms);
}
int write_full(int fd, const void *buffer, size_t count) {
  return transfer(fd, (void *)buffer, count, 1, clock_ms() + timeout_ms);
}
int dial_tcp(const char *host, const char *port) {
  struct addrinfo hints = {0}, *addresses = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  if (getaddrinfo(host, port, &hints, &addresses) != 0) {
    errno = EHOSTUNREACH;
    return -1;
  }
  int fd = -1, saved = ECONNREFUSED;
  int64_t deadline = clock_ms() + timeout_ms;
  for (struct addrinfo *address = addresses; address;
       address = address->ai_next) {
    fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (fd < 0)
      continue;
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
      saved = errno;
      close(fd);
      fd = -1;
      continue;
    }
    int rc = connect(fd, address->ai_addr, address->ai_addrlen);
    if (rc < 0 && errno == EINPROGRESS) {
      if (ready(fd, POLLOUT, deadline) == 0) {
        socklen_t length = sizeof(saved);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &saved, &length) == 0 &&
            saved == 0)
          rc = 0;
      }
    }
    if (rc == 0)
      break;
    saved = errno ? errno : saved;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(addresses);
  if (fd < 0)
    errno = saved;
  return fd;
}
static uint16_t u16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] << 8) | p[1];
}
static uint32_t u32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}
int read_frame(int fd, struct MsgHeader *header, uint8_t **body) {
  uint8_t wire[12];
  *body = NULL;
  int64_t deadline = clock_ms() + timeout_ms;
  int result = transfer(fd, wire, sizeof(wire), 0, deadline);
  if (result != 0)
    return result;
  header->magic = u32(wire);
  header->version = u16(wire + 4);
  header->type = u16(wire + 6);
  header->length = u32(wire + 8);
  if (header->magic != MAGIC || header->version != VERSION ||
      header->length > MAX_FRAME_SIZE || header->type < 1 || header->type > 5) {
    errno = EPROTO;
    return -1;
  }
  if ((header->type == AUTH_CHALLENGE &&
       (!header->length || header->length > 1024)) ||
      (header->type == CIPHER_MAP && header->length != 256) ||
      (header->type == ACK && header->length)) {
    errno = EPROTO;
    return -1;
  }
  if (!header->length)
    return 0;
  *body = malloc(header->length);
  if (!*body)
    return -1;
  if (transfer(fd, *body, header->length, 0, deadline) != 0) {
    free(*body);
    *body = NULL;
    errno = EPROTO;
    return -1;
  }
  return 0;
}
int write_frame(int fd, uint16_t type, const uint8_t *body, uint32_t length) {
  if (length > MAX_FRAME_SIZE || (length && !body)) {
    errno = EINVAL;
    return -1;
  }
  uint8_t header[12] = {(MAGIC >> 24) & 255,
                        (MAGIC >> 16) & 255,
                        (MAGIC >> 8) & 255,
                        MAGIC & 255,
                        0,
                        VERSION,
                        (uint8_t)(type >> 8),
                        (uint8_t)type,
                        (uint8_t)(length >> 24),
                        (uint8_t)(length >> 16),
                        (uint8_t)(length >> 8),
                        (uint8_t)length};
  int64_t deadline = clock_ms() + timeout_ms;
  if (transfer(fd, header, sizeof(header), 1, deadline) < 0)
    return -1;
  return length ? transfer(fd, (void *)body, length, 1, deadline) : 0;
}
