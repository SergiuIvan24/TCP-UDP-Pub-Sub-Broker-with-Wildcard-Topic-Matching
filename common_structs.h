// common_structs.h
#ifndef COMMON_STRUCTS_H
#define COMMON_STRUCTS_H
#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

#define MAX_CONNECTIONS 100      // Numar maxim de conexiuni TCP simultane
#define MAX_CLIENT_ID 10         // Lungimea maxima a ID-ului de client
#define TOPIC_SIZE 50            // Lungimea maxima a unui topic
#define TYPE_SIZE 1              // Dimensiunea campului de tip de date
#define MAX_CONTENT_SIZE 1500    // Dimensiunea maxima a continutului unui mesaj
#define MAX_UDP_SIZE (TOPIC_SIZE + TYPE_SIZE + MAX_CONTENT_SIZE)  // Dimensiunea maxima a unui pachet UDP
#define INITIAL_HASHTABLE_SIZE 64  // Dimensiunea initiala a hashmap-ului
#define INT_TYPE 0               // Identificator pentru tip INT
#define SHORT_REAL_TYPE 1        // Identificator pentru tip SHORT_REAL
#define FLOAT_TYPE 2             // Identificator pentru tip FLOAT
#define STRING_TYPE 3            // Identificator pentru tip STRING

// tipuri de mesaje
typedef enum {
    MESSAGE_TYPE_UDP,
    MESSAGE_TYPE_TCP
} MessageType;

typedef struct TrieNode {
    struct TrieNode* children[128];  // Copii pentru caractere normale
    struct TrieNode* plus;           // Copil pentru wildcard '+'
    struct TrieNode* star;           // Copil pentru wildcard '*'
    bool is_end;                     // Marcheaza sfarsitul unui pattern
    uint32_t subscriber_count;       // Numar de abonati la acest pattern
    char* pattern;                   // Pattern-ul complet
    uint16_t depth;                  // Adancimea nodului in trie
} TrieNode;

typedef struct {
    MessageType type;        // Tipul mesajului (UDP sau TCP)

    char *sender_ip;         // IP-ul expeditorului
    uint16_t sender_port;    // Portul expeditorului

    char *topic;             // Topicul mesajului
    uint8_t data_type;       // Tipul de date al continutului
    char *data_type_str;     // tipul de date ca string

    char *cont_brut;         // Continutul brut
    char *cont_formatat;     // Continutul formatat pentru TCP

    int content_len;         // Lungimea continutului
} message;

typedef struct Client {
    int fd;                      // Descriptorul de fisier al socket-ului
    char *id;                    // ID-ul clientului
    bool connected;              // Flag pentru starea de conectare
    TrieNode* subscription_trie; // Trie pentru pattern-urile de abonament
    bool is_occupied;            // Flag pentru ocuparea slotului in hashmap
} Client;

typedef struct {
    Client *clients;         // Array de clienti
    size_t size;             // Dimensiunea curenta a hashmap-ului
    size_t count;            // Numarul de clienti stocati
    float prag_redim;        // Pragul pentru redimensionare
} ClientsHashMap;

message* create_message();
void free_message(message *msg);

#endif // COMMON_STRUCTS_H