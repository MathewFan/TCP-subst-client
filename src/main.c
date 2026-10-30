#define _POSIX_C_SOURCE 200809L
#include "common.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 4 && argc != 5) {
    fprintf(stderr,
            "Usage: SUBST_SECRET=... %s HOST PORT USER [legacy-secret]\n",
            argv[0]);
    return 2;
  }
  const char *secret = argc == 5 ? argv[4] : getenv("SUBST_SECRET");
  if (!secret || !*secret) {
    fprintf(stderr, "SUBST_SECRET is required\n");
    return 2;
  }
  const char *timeout = getenv("SUBST_TIMEOUT_MS");
  if (timeout) {
    char *end;
    errno = 0;
    long value = strtol(timeout, &end, 10);
    if (errno || *end || value < 10 || value > 600000) {
      fprintf(stderr, "invalid SUBST_TIMEOUT_MS\n");
      return 2;
    }
    net_set_timeout_ms((int)value);
  }
  signal(SIGPIPE, SIG_IGN);
  int fd = dial_tcp(argv[1], argv[2]);
  if (fd < 0) {
    perror("connect");
    return 1;
  }
  struct SessionStats stats = {0};
  int result = handle_session_ex(fd, argv[3], secret, &stats);
  close(fd);
  if (getenv("SUBST_STATS"))
    fprintf(stderr,
            "{\"frames\":%llu,\"plaintext_bytes\":%llu,\"acks\":%llu,"
            "\"success\":%s}\n",
            (unsigned long long)stats.frames,
            (unsigned long long)stats.plaintext_bytes,
            (unsigned long long)stats.acks, result ? "false" : "true");
  if (result)
    fprintf(stderr, "session failed: malformed, truncated, out-of-order, or "
                    "timed-out stream\n");
  return result ? 1 : 0;
}
