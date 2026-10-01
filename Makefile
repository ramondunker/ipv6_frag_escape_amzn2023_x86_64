CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror
LDFLAGS ?= -static

TARGET := IPV6_FRAG_ESCAPE_amzn2023_x86_64
OBJS := IPV6_FRAG_ESCAPE_amzn2023.o btfcheck.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

IPV6_FRAG_ESCAPE_amzn2023.o: IPV6_FRAG_ESCAPE_amzn2023.c btfcheck.h
	$(CC) $(CFLAGS) -c -o $@ IPV6_FRAG_ESCAPE_amzn2023.c

btfcheck.o: btfcheck.c btfcheck.h
	$(CC) $(CFLAGS) -c -o $@ btfcheck.c

clean:
	rm -f $(TARGET) $(OBJS)
