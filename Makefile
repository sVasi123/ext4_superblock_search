# Makefile for find_ext4_superblocks

CC=gcc
CFLAGS=-Wall -Wextra -O2 -std=c99
TARGET=find_ext4_superblocks
SOURCE=find_ext4_superblocks.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)
