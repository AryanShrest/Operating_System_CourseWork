# Makefile - ST5004CEM Task 3: Secure File Management System
# Build:  make
# Run:    ./sfm
# Clean:  make clean

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE
LDFLAGS =

SRC     = main.c auth.c file_ops.c permission.c
OBJ     = $(SRC:.c=.o)
TARGET  = sfm

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

reset:
	rm -f users.txt permissions.txt
	rm -rf files

.PHONY: all clean reset
