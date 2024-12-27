# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread -pedantic -lssl -lcrypto -fsanitize=address -fsanitize=undefined

# Target executable
TARGET = prx

# Source files
SRCS = main.c proxy/proxy_server.c
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Build the target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^
	@rm -f $(OBJS)


# Compile object files
%.o: %.c proxy/proxy_server.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean