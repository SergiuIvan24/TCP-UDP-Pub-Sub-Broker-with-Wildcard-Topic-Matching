CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -D_GNU_SOURCE
LDFLAGS =

.PHONY: all clean

all: server subscriber

server: server.o hashmap_and_trie.o
	$(CC) $(CFLAGS) server.o hashmap_and_trie.o -o server $(LDFLAGS)


subscriber: subscriber.o
	$(CC) $(CFLAGS) subscriber.o -o subscriber $(LDFLAGS)


server.o: server.c hashmap_and_trie.h
	$(CC) $(CFLAGS) -c server.c -o server.o

subscriber.o: subscriber.c
	$(CC) $(CFLAGS) -c subscriber.c -o subscriber.o


hashmap_list.o: hashmap_and_trie.c hashmap_and_trie.h
	$(CC) $(CFLAGS) -c hashmap_and_trie.c -o hashmap_and_trie.o


clean:
	rm -f server subscriber *.o