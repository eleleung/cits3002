CC=gcc
CFLAGS=-std=gnu99 -Wall -Werror -pedantic
LFLAGS=-lssl -lcrypto

make: client.c
	$(CC) client.c $(CFLAGS) $(LFLAGS) -o client

clean:
	$(RM) client *.o *~
