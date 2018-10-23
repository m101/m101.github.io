CC=gcc
CFLAGS=-m32 -g
LDFLAGS=

all: vm

vm: vm.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean mrproper

clean:

mrproper: clean
	rm vm
