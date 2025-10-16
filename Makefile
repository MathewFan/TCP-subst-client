CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic -std=c17 -Iinclude
LDFLAGS ?=
LDLIBS = -lssl -lcrypto

SRC = src/main.c src/net.c src/proto.c src/cipher.c
BIN = subst_client

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

fmt:
	clang-format -i $(SRC) include/common.h

clean:
	rm -f $(BIN)

