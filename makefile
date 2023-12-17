CC = gcc
CFLAGS = -Wall -Wpedantic -std=c99

gk2:
	$(CC) gk2.c -o gk2a.bin $(CFLAGS)

gk2-ctx:
	$(CC) gk2-ctx.c -o ctxa.bin $(CFLAGS)
