// hashmap_list.h
#ifndef HASHMAP_LIST_H
#define HASHMAP_LIST_H

#include <stdbool.h>
#include "common_structs.h"

// Creaza un mesaj nou cu alocari dinamice pentru toate campurile
message* create_message();
// Elibereaza memoria alocata pentru un mesaj si toate componentele sale
void free_message(message *msg);

// Creeaza un hashmap nou pentru stocarea clientilor
ClientsHashMap* create_clients_hashmap();
// Adauga un client in hashmap cu un fd si id dat
void add_client_to_hashmap(ClientsHashMap *map, int fd, const char *id);
// Marcheaza un client ca fiind deconectat (dar pastreaza datele)
bool mark_client_disconnected(ClientsHashMap *map, int fd);
// Elibereaza memoria alocata pentru hashmap si toti clientii
void free_clients_hashmap(ClientsHashMap *map);
// Calculeaza hashul pentru un id de client
unsigned long client_hash(const char *id, size_t table_size);
// Redimensioneaza hashmap-ul cand este prea plin
bool resize_hashmap(ClientsHashMap *map);
// Gaseste urmatorul slot liber
unsigned long find_next_slot(ClientsHashMap *map, unsigned long index);

// Creeaza un client nou
Client* create_client(int fd, const char *id);
// Elibereaza memoria alocata pentru un client
void free_client(Client *client);
// Gaseste un client dupa id
Client* find_client_by_id(ClientsHashMap *map, const char *id);
// Gaseste un client dupa descriptorul de fisier
Client* find_client_by_fd(ClientsHashMap *map, int fd);

// Extrage toate pattern-urile dintr-un trie pentru a le putea verifica
void pattern_construct(TrieNode* node, char* prefix, char*** patterns, int* count, int* capacity);
// Adauga un abonament pentru un client
bool client_add_subscription(Client *client, const char *topic_or_pattern);
// Elimina un abonament pentru un client
bool client_remove_subscription(Client *client, const char *topic_or_pattern);
// Functie generala pentru gestionarea abonamentelor (subscribe/unsubscribe)
bool manage_subscription(Client *client, const char *topic_or_pattern, bool is_subscribe);
// Verifica daca un topic se potriveste cu un pattern de abonament
bool topic_matches_pattern(const char* topic, const char* pattern);

// Creeaza un nod nou pentru trie
TrieNode* create_trie_node();
// Creeaza un nod nou cu o anumita adancime specificata
TrieNode* create_trie_node_with_depth(uint16_t depth);
// Elibereaza memoria alocata pentru un trie intreg
void free_trie(TrieNode* root);
// Insereaza un pattern in trie
void insert_pattern(TrieNode* root, const char* pattern);
// Creeaza un trie nou si insereaza direct un pattern
TrieNode* init_insert(const char* pattern);

#endif // HASHMAP_LIST_H