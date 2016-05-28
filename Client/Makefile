CC=gcc
CFLAGS=-std=gnu99 -Wall -Werror -pedantic
LFLAGS=-lssl -lcrypto

make: client.c
	$(CC) $(CFLAGS) $(LFLAGS) -o client client.c

clean:
	$(RM) client *.o *~
