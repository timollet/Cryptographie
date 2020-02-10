CC = gcc

INCLUDE = -I/usr/local/include -I/usr/include
LIB = -L/usr/local/lib -L/usr/lib -lm -lssl -lcrypto -g -std=c99 -Wall

all: aes_projet

aes_projet: aes_projet.c
	$(CC) -o aes_projet $(INCLUDE) aes_projet.c $(LIB)

clean:
	-rm *.o *~
	-rm aes_projet

