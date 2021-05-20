TARGET = main

all: $(TARGET)

CC = gcc
LD = gcc

CFLAGS = -g -Wall -Iinclude
LDFLAGS = -L.

LIBS = 

HDRS = ./include/*.h

SRCS = main.c trie.c
OBJS = $(patsubst %.c,%.o,$(SRCS))

$(OBJS) : %.o : %.c include/*.h
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS) 

clean:
	rm -f *.o $(TARGET) $(LIBIP)

tags: $(SRCS) $(HDRS)
	ctags $(SRCS) $(HDRS)
