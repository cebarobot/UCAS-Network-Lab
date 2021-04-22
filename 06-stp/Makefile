TARGET := stp

all : $(TARGET)

CC = gcc
LD = gcc

CFLAGS = -g -Wall -Iinclude
LDFLAGS = 

LIBS = -lpthread

SRCS = stp.c stp_timer.c main.c broadcast.c device_internal.c mac.c 

OBJS = $(patsubst %.c,%.o,$(SRCS))

$(OBJS) : %.o : %.c include/*.h
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS) 

clean:
	rm -f *.o $(TARGET)

tags: *.c include/*.h
	ctags *.c include/*.h
