#include "common.h"
#include <stdio.h>
#include <stdlib.h>

static void usage(const char *prog) {
  fprintf(stderr, "Usage: %s <host> <port> <username> <secret>\n", prog);
}

int main(int argc, char **argv) {
  if (argc != 5) { usage(argv[0]); return 2; }
  const char *host = argv[1], *port = argv[2], *user = argv[3], *secret = argv[4];

  int fd = dial_tcp(host, port);
  if (fd < 0) { perror("dial_tcp"); return 1; }

  if (handle_session(fd, user, secret) != 0) {
    fprintf(stderr, "session error\n");
    return 1;
  }
  return 0;
}
