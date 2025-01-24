
CC_32 = gcc
CC_64 = gcc

CFLAGS_32 = -m32 
CFLAGS_64 = -m64

SOURCES = test_1.c test_2.c test_3.c test_4.c test_5.c

BIN_32 = $(patsubst %.c,%_32,$(SOURCES))

BIN_64 = $(patsubst %.c,%_64,$(SOURCES))

all: $(BIN_32) $(BIN_64)

%_32: %.c
	$(CC_32) $(CFLAGS_32) -o $@ $<

%_64: %.c
	$(CC_64) $(CFLAGS_64) -o $@ $<
clean:
	rm -f *_32 *_64


check_i386:
	@if ! gcc -m32 -v > /dev/null 2>&1; then \
		echo "Le support i386 n'est pas disponible. Installation..."; \
		if command -v apt-get > /dev/null; then \
			sudo apt-get update && sudo apt-get install -y gcc-multilib libc6-dev-i386; \
		fi \
	else \
		echo "Le support i386 est déjà disponible."; \
	fi