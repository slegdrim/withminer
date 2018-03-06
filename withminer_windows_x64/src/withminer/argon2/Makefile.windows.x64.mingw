
TARGET = libargon2

SRCS = argon2.c core.c blake2/blake2b.c thread.c encoding.c opt.c

OBJS = $(SRCS:.c=.o)

CFLAGS = -std=c99 -O3 -Wall -g -pthread -march=native -I.

LIB_CFLAGS = rcs

all:	$(OBJS)
	$(AR) $(LIB_CFLAGS) $(TARGET).a $(OBJS)

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $^

%.c:

clean:
	rm -rf $(OBJS) $(TARGET).a
