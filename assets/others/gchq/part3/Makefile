CC=gcc
CFLAGS=-m32 -g
LDFLAGS=-lcrypt

all: reversed

reversed: reversed.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean mrproper

clean:

mrproper: clean
	rm reversed
