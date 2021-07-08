CC = gcc
CFLAGS = -g -Wall -Iinclude
LIBS = -lpthread -ldl -lrt

SRCS := $(wildcard $(SRC_DIR)*.c)
OBJS := $(SRCS:.c=.o)
TARGET := http_server

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJS) : %.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean: 
	rm -rf $(SRC_DIR)*.o $(TARGET)

.PHONY:clean
