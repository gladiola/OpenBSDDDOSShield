PROG=	ddosshield
SRCS=	ddosshield.c

CC=	cc
CFLAGS=	-Wall -Wextra -pedantic -std=c99 -O2

.PHONY: all clean install

all: $(PROG)

$(PROG): $(SRCS)
	$(CC) $(CFLAGS) -o $(PROG) $(SRCS)

install: $(PROG)
	install -m 0755 $(PROG) /usr/local/sbin/$(PROG)

clean:
	rm -f $(PROG)
