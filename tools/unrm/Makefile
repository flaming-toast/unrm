# Makefile for unrm tool for ext4

CFLAGS += -static

all: unrm

%: %.c
	$(CC) $(CFLAGS) -o $@ $^
clean:
	$(RM) unrm
