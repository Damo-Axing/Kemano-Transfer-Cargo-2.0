CC = gcc
CFLAGS = -std=c11 -D_GNU_SOURCE -Wall -Wextra -O3 -march=native -Iinclude
LDFLAGS = -lsodium -lpthread -lm

TARGETS = bin/ktc-server bin/ktc-client bin/ktc-relay bin/ktc-keygen
TESTS = test_crypto test_packets test_handshake

SRC = src/crypto.c src/packets.c src/handshake.c src/session.c \
      src/bbr.c src/sack.c src/masking.c src/utils.c

all: $(TARGETS)

bin/ktc-server: src/server.c $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bin/ktc-client: src/client.c $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bin/ktc-relay: src/relay.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bin/ktc-keygen: src/keygen.c $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TESTS)
	@for t in $(TESTS); do ./tests/$$t; done

test_crypto: tests/test_crypto.c src/crypto.c
	$(CC) $(CFLAGS) -o tests/$@ $^ $(LDFLAGS)

test_packets: tests/test_packets.c src/crypto.c src/packets.c
	$(CC) $(CFLAGS) -o tests/$@ $^ $(LDFLAGS)

test_handshake: tests/test_handshake.c src/crypto.c src/packets.c src/handshake.c
	$(CC) $(CFLAGS) -o tests/$@ $^ $(LDFLAGS)

sanitize: CFLAGS += -fsanitize=address,undefined -g
sanitize: clean all

clean:
	rm -f $(TARGETS) tests/test_*

install: all
	install -m 0755 bin/ktc-server /usr/local/bin/
	install -m 0755 bin/ktc-client /usr/local/bin/
	install -m 0755 bin/ktc-relay /usr/local/bin/
	install -m 0755 bin/ktc-keygen /usr/local/bin/

.PHONY: all test sanitize clean install
