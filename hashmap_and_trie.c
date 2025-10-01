#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "hashmap_and_trie.h"
#include "common_structs.h"

message* create_message() {
    message* msg = (message*)malloc(sizeof(message));
    if (!msg) return NULL;

    msg->sender_ip = NULL;
    msg->topic = NULL;
    msg->data_type_str = NULL;
    msg->cont_brut = NULL;
    msg->cont_formatat = NULL;

    msg->sender_ip = (char*)malloc(INET_ADDRSTRLEN);
    msg->topic = (char*)malloc(TOPIC_SIZE + 1);
    msg->data_type_str = (char*)malloc(20);
    msg->cont_brut = (char*)malloc(MAX_CONTENT_SIZE + 1);
    msg->cont_formatat = (char*)malloc(MAX_CONTENT_SIZE + 1);

    if (!msg->sender_ip || !msg->topic || !msg->data_type_str ||
        !msg->cont_brut || !msg->cont_formatat) {
        free_message(msg);
        return NULL;
    }

    memset(msg->sender_ip, 0, INET_ADDRSTRLEN);
    memset(msg->topic, 0, TOPIC_SIZE + 1);
    memset(msg->data_type_str, 0, 20);
    memset(msg->cont_brut, 0, MAX_CONTENT_SIZE + 1);
    memset(msg->cont_formatat, 0, MAX_CONTENT_SIZE + 1);

    msg->sender_port = 0;
    msg->data_type = 0;
    msg->content_len = 0;

    return msg;
}

void free_message(message *msg) {
    if (!msg) return;

    free(msg->sender_ip);
    free(msg->topic);
    free(msg->data_type_str);
    free(msg->cont_brut);
    free(msg->cont_formatat);
    free(msg);
}

TrieNode* create_trie_node() {
    TrieNode* node = (TrieNode*)malloc(sizeof(TrieNode));
    if (!node) return NULL;

    memset(node->children, 0, sizeof(node->children));
    node->plus = NULL;
    node->star = NULL;
    node->is_end = false;
    node->subscriber_count = 0;
    node->pattern = NULL;
    node->depth = 0;

    return node;
}

TrieNode* create_trie_node_with_depth(uint16_t depth) {
    TrieNode* node = create_trie_node();
    if (node) {
        node->depth = depth;
    }
    return node;
}

void free_trie(TrieNode* root) {
    if (!root) return;
    for (int i = 0; i < 128; i++) {
        if (root->children[i]) {
            free_trie(root->children[i]);
        }
    }

    if (root->plus) free_trie(root->plus);
    if (root->star) free_trie(root->star);

    if (root->pattern) {
        free(root->pattern);
    }

    free(root);
}

TrieNode* init_insert(const char* pattern) {
    TrieNode* root = create_trie_node();
    if (root && pattern) {
        insert_pattern(root, pattern);
    }
    return root;
}

void insert_pattern(TrieNode* node, const char* pattern) {
    // Am ajuns la sfarsitul pattern-ului
    if (*pattern == '\0') {
        node->is_end = true;
        node->subscriber_count++;
        // Salveaza pattern-ul complet daca nu este deja salvat
        if (node->pattern == NULL) {
            node->pattern = strdup(pattern - node->depth);
            if (!node->pattern) {
                return;
            }
        }
        return;
    }

    switch (*pattern) {
        // Daca este '+', insereaza in nodul corespunzator si continua cu restul pattern-ului
        case '+':
            if (!node->plus) {
                node->plus = create_trie_node_with_depth(node->depth + 1);
            }
            insert_pattern(node->plus, pattern + 1);
            break;
        case '*':
            if (!node->star) {
                node->star = create_trie_node_with_depth(node->depth + 1);
            }
            insert_pattern(node->star, pattern + 1);
            break;
        // daca nu sunt wildcard-uri, inseamna ca este un caracter normal
        // insereaza in nodul corespunzator si continua cu restul pattern-ului
        default:
            if (!node->children[(unsigned char)*pattern]) {
                node->children[(unsigned char)*pattern] = create_trie_node_with_depth(node->depth + 1);
            }
            insert_pattern(node->children[(unsigned char)*pattern], pattern + 1);
            break;
    }
}

bool topic_matches_pattern(const char* topic, const char* pattern) {
    if (!topic || !pattern) return false;
     // Wildcard "*" singur se potriveste cu orice
    if (strcmp(pattern, "*") == 0) return true;

    const char* t = topic;
    const char* p = pattern;

    while (*t || *p) {
        if (*p == '*') {
            //daca * e ultimul caracter, se potriveste cu orice
            if (*(p+1) == '\0') {
                return true;
            }
            // Daca urmatorul caracter este '/', cautam urmatorul segment
            if (*(p+1) == '/') {
                const char* next_segment = p + 2;
                const char* pos = t;
                while (*pos) {
                    if (*pos == '/') {
                        if (topic_matches_pattern(pos + 1, next_segment)) {
                            return true;
                        }
                    }
                    pos++;
                }
                return false;
            }
            return false;
        }
        // Wildcard "+" se potriveste cu un segment intreg
        else if (*p == '+') {
            while (*t && *t != '/') {
                t++;
            }
            p++;
            if (*t == '/' && *p == '/') {
                t++;
                p++;
                continue;
            }
            if ((*t == '/' && *p == '\0') || (*t == '\0' && *p == '/')) {
                return false;
            }
            if (*t == '\0' && *p == '\0') {
                return true;
            }
            if (*t == '\0' || *p == '\0') {
                return false;
            }
        }
        // Caractere normale, deci trebuie sa fie identice.
        else if (*p == *t) {
            p++;
            t++;
        }
        else {
            return false;
        }
    }
    // Am ajuns la sfarsit deci se potrivesc
    if(*t == '\0')
        if(*p == '\0')
            return true;
    return false;
}

void pattern_construct(TrieNode* node, char* prefix, char*** patterns, int* count, int* capacity) {
    if (!node) return;

    // Daca este sfarsit de pattern, adaugam in lista
    if (node->is_end) {
        if (*count >= *capacity) {
            if (*capacity > 0) {
                *capacity *= 2;
            } else {
                *capacity = 4;
            }
            if (!(*patterns = realloc(*patterns, *capacity * sizeof(char*)))) return;
        }

        char* new_pattern = strdup(node->pattern ? node->pattern : prefix);
        if (!new_pattern) return;

        (*patterns)[*count] = new_pattern;
        (*count)++;
    }

    char new_prefix[strlen(prefix) + 2];
    // parcurgem toti copiii
    for (int i = 0; i < 128; i++) {
        if (node->children[i]) {
            sprintf(new_prefix, "%s%c", prefix, (char)i);
            pattern_construct(node->children[i], new_prefix, patterns, count, capacity);
        }
    }
    // exploram nodurile wildcard
    if (node->plus) {
        sprintf(new_prefix, "%s+", prefix);
        pattern_construct(node->plus, new_prefix, patterns, count, capacity);
    }

    if (node->star) {
        sprintf(new_prefix, "%s*", prefix);
        pattern_construct(node->star, new_prefix, patterns, count, capacity);
    }
}

bool manage_subscription(Client *client, const char *topic_or_pattern, bool is_subscribe) {
    if (!client || !topic_or_pattern || !client->subscription_trie) return false;

    if (is_subscribe) {
        //adaugam un nou pattern
        insert_pattern(client->subscription_trie, topic_or_pattern);
        return true;
    } else {
        //eliminam un pattern, si cream un nou trie fara acel pattern
        TrieNode* new_trie = create_trie_node();
        if (!new_trie) return false;

        char** patterns = NULL;
        int pattern_count = 0;
        int pattern_capacity = 0;

        pattern_construct(client->subscription_trie, "", &patterns, &pattern_count, &pattern_capacity);

        bool found = false;
        for (int i = 0; i < pattern_count; i++) {
            if (strcmp(patterns[i], topic_or_pattern) != 0) {
                insert_pattern(new_trie, patterns[i]);
            } else {
                found = true;
            }
        }

        for (int i = 0; i < pattern_count; i++) {
            free(patterns[i]);
        }
        free(patterns);

        free_trie(client->subscription_trie);
        client->subscription_trie = new_trie;

        return found;
    }
}

bool client_add_subscription(Client *client, const char *topic_or_pattern) {
    return manage_subscription(client, topic_or_pattern, true);
}

bool client_remove_subscription(Client *client, const char *topic_or_pattern) {
    return manage_subscription(client, topic_or_pattern, false);
}

unsigned long client_hash(const char *id, size_t table_size) {
    unsigned long hash = 5381;
    int c;

    while ((c = *id++)) {
        hash = hash * 33 + c;
    }

    return hash % table_size;
}

ClientsHashMap* create_clients_hashmap() {
    ClientsHashMap *map = malloc(sizeof(ClientsHashMap));
    if (!map) return NULL;

    map->clients = calloc(INITIAL_HASHTABLE_SIZE, sizeof(Client));
    if (!map->clients) {
        free(map);
        return NULL;
    }
    // Initializeaza toti clientii ca fiind neocupati
    for (size_t i = 0; i < INITIAL_HASHTABLE_SIZE; i++) {
        map->clients[i].id = NULL;
        map->clients[i].subscription_trie = NULL;
        map->clients[i].is_occupied = false;
    }

    map->size = INITIAL_HASHTABLE_SIZE;
    map->count = 0;
    map->prag_redim = 0.75;

    return map;
}

Client* create_client(int fd, const char *id) {
    Client *client = (Client*)malloc(sizeof(Client));
    if (!client) return NULL;

    client->fd = fd;
    client->id = strdup(id);
    if (!client->id) {
        free(client);
        return NULL;
    }

    client->connected = true;
    client->subscription_trie = create_trie_node();
    client->is_occupied = true;

    return client;
}

// Gaseste urmatorul slot liber
unsigned long find_next_slot(ClientsHashMap *map, unsigned long index) {
    unsigned long i = index;
    do {
        if (!map->clients[i].is_occupied) {
            return i;
        }
        i = (i + 1) % map->size;
    } while (i != index);
    //hashmap-ul este plin
    return map->size;
}

Client* find_client_by_id(ClientsHashMap *map, const char *id) {
    if (!map || !id) return NULL;

    unsigned long index = client_hash(id, map->size);
    unsigned long start_index = index;

    do {
        if (map->clients[index].is_occupied &&
            map->clients[index].id &&
            strcmp(map->clients[index].id, id) == 0) {
            return &map->clients[index];
        }
        index = (index + 1) % map->size;
    } while (index != start_index);

    return NULL;
}
Client* find_client_by_fd(ClientsHashMap *map, int fd) {
    if (!map || fd < 0) return NULL;

    for (size_t i = 0; i < map->size; i++) {
        if (map->clients[i].is_occupied &&
            map->clients[i].fd == fd &&
            map->clients[i].connected) {
            return &map->clients[i];
        }
    }

    return NULL;
}

void add_client_to_hashmap(ClientsHashMap *map, int fd, const char *id) {
    if (!map || !id) return;
    // Verificam daca clientul exista deja
    Client *existing = find_client_by_id(map, id);
    if (existing) {
        if (!existing->connected) {
            //reconectam clientul deconectat
            existing->fd = fd;
            existing->connected = true;
        }
        return;
    }

    float load_factor = (float)map->count / (float)map->size;
    if (load_factor >= map->prag_redim) {
        if (!resize_hashmap(map)) {
            printf("Error: Failed to resize hashmap\n");
            return;
        }
    }

    unsigned long index = client_hash(id, map->size);
    unsigned long slot = find_next_slot(map, index);

    if (slot == map->size) {
        printf("Error: Clients hashmap is full\n");
        return;
    }
    //initializeaza un nou client
    Client *new_slot = &map->clients[slot];
    new_slot->fd = fd;
    new_slot->id = strdup(id);
    if (!new_slot->id) {
        printf("Error: Memory allocation failed\n");
        return;
    }

    new_slot->connected = true;
    new_slot->subscription_trie = create_trie_node();
    new_slot->is_occupied = true;

    map->count++;
}

bool mark_client_disconnected(ClientsHashMap *map, int fd) {
    Client *client = find_client_by_fd(map, fd);
    if (client) {
        client->connected = false;
        printf("Client %s disconnected.\n", client->id);
        fflush(stdout);
        return true;
    }
    return false;
}
//redimensionam, dubland marimea
bool resize_hashmap(ClientsHashMap *map) {
    size_t new_size = map->size * 2;
    Client *new_clients = calloc(new_size, sizeof(Client));
    if (!new_clients) return false;

    for (size_t i = 0; i < new_size; i++) {
        new_clients[i].id = NULL;
        new_clients[i].subscription_trie = NULL;
        new_clients[i].is_occupied = false;
    }

    for (size_t i = 0; i < map->size; i++) {
        if (map->clients[i].is_occupied && map->clients[i].id) {
            unsigned long new_index = client_hash(map->clients[i].id, new_size);

            while (new_clients[new_index].is_occupied) {
                new_index = (new_index + 1) % new_size;
            }

            new_clients[new_index] = map->clients[i];
        }
    }

    free(map->clients);

    map->clients = new_clients;
    map->size = new_size;

    return true;
}


void free_clients_hashmap(ClientsHashMap *map) {
    if (!map) return;

    for (size_t i = 0; i < map->size; i++) {
        if (map->clients[i].is_occupied) {
            free_client(&map->clients[i]);
        }
    }

    free(map->clients);
    free(map);
}

void free_client(Client *client) {
    if (!client) return;

    if (client->id) {
        free(client->id);
    }

    if (client->subscription_trie) {
        free_trie(client->subscription_trie);
    }
}