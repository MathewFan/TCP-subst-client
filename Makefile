CC ?= cc
PKG_CONFIG ?= pkg-config
CPPFLAGS += -Iinclude $(shell $(PKG_CONFIG) --cflags openssl)
CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic -std=c17
LDLIBS += $(shell $(PKG_CONFIG) --libs openssl)
SRC = src/main.c src/net.c src/proto.c src/cipher.c
BIN = subst_client
.PHONY: all test sanitize clean
all: $(BIN)
$(BIN): $(SRC) include/common.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)
test: $(BIN)
	python3 -m unittest discover -s test -p 'test_*.py' -v
sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS='-O1 -g -Wall -Wextra -Wpedantic -std=c17 -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined' test
clean:
	rm -f $(BIN)
