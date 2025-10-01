#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include "hashmap_and_trie.h"
#include "common_structs.h"

#define BUFLEN 2048
//folosim send_all pt a ne asigura ca trimitem tot mesajul
int send_all(int sockfd, const void *buffer, size_t len) {
    if (len == 0) return 0;
    ssize_t bytes_sent = send(sockfd, buffer, len, 0);
    if (bytes_sent <= 0) return -1;

    if ((size_t)bytes_sent == len) return bytes_sent;
    //trimitem recursiv restul datelor
    int remaining = send_all(sockfd, (const char *)buffer + bytes_sent, len - bytes_sent);
    if (remaining < 0) return -1;

    return bytes_sent + remaining;
}

static int INT_FORMAT(message *msg) {
    uint8_t sign_byte = (uint8_t)msg->cont_brut[0];
    uint32_t val;
    memcpy(&val, msg->cont_brut + 1, sizeof(uint32_t));
    uint32_t value = ntohl(val);

    if (sign_byte == 1 && value != 0) {
        snprintf(msg->cont_formatat, MAX_CONTENT_SIZE, "-%u", value);
    } else {
        snprintf(msg->cont_formatat, MAX_CONTENT_SIZE, "%u", value);
    }
    return 1;
}

static int SHORT_REAL_FORMAT(message *msg) {
    uint16_t val;
    memcpy(&val, msg->cont_brut, sizeof(uint16_t));
    uint16_t value = ntohs(val);
    float real_value = (float)value / 100.0f;

    snprintf(msg->cont_formatat, MAX_CONTENT_SIZE, "%.2f", real_value);
    return 1;
}

static int FLOAT_FORMAT(message *msg) {
    uint8_t sign = msg->cont_brut[0];
    uint32_t abs_value = ntohl(*(uint32_t*)(msg->cont_brut + 1));
    uint8_t power = msg->cont_brut[5];

    double valoare = abs_value;
    for (uint8_t i = 0; i < power; i++)
        valoare /= 10.0;

    if (sign == 1)
        valoare = -valoare;

    snprintf(msg->cont_formatat, MAX_CONTENT_SIZE, "%.*f", power, valoare);
    return 1;
}

static int STRING_FORMAT(message *msg) {
    strncpy(msg->cont_formatat, msg->cont_brut, MAX_CONTENT_SIZE);
    msg->cont_formatat[MAX_CONTENT_SIZE] = '\0';
    return 1;
}

static int UNKNOWN_FORMAT(message *msg) {
    snprintf(msg->cont_formatat, MAX_CONTENT_SIZE, "Invalid");
    return 0;
}

int format_message_for_tcp(message *msg) {
    int format_result = 0;
    msg->type = MESSAGE_TYPE_TCP;

    switch (msg->data_type) {
        case INT_TYPE:
            strcpy(msg->data_type_str, "INT");
            format_result = INT_FORMAT(msg);
            break;
        case SHORT_REAL_TYPE:
            strcpy(msg->data_type_str, "SHORT_REAL");
            format_result = SHORT_REAL_FORMAT(msg);
            break;
        case FLOAT_TYPE:
            strcpy(msg->data_type_str, "FLOAT");
            format_result = FLOAT_FORMAT(msg);
            break;
        case STRING_TYPE:
            strcpy(msg->data_type_str, "STRING");
            format_result = STRING_FORMAT(msg);
            break;
        default:
            strcpy(msg->data_type_str, "UNKNOWN");
            format_result = UNKNOWN_FORMAT(msg);
    }
    return format_result;
}
//verifica daca un client este abonat la un topic
int client_subscribed(Client *client, const char *topic) {
    if (!client || !client->subscription_trie || !topic) return 0;

    //extrage toate pattern-urile din trie
    char** patterns = NULL;
    int pattern_count = 0, pattern_capacity = 0;
    pattern_construct(client->subscription_trie, "", &patterns, &pattern_count, &pattern_capacity);

    bool result = false;
    //verifica daca topic-ul se potriveste cu vreun pattern
    for (int i = 0; i < pattern_count; i++) {
        if (topic_matches_pattern(topic, patterns[i])) {
            result = true;
            break;
        }
    }

    for (int i = 0; i < pattern_count; i++) {
        free(patterns[i]);
    }
    free(patterns);

    if (result) {
        return 1;
    } else {
        return 0;
    }
}

void process_udp_message(message *msg, ClientsHashMap *clients_map) {
    format_message_for_tcp(msg);
    // Calculeaza dimensiunea necesara pentru mesajul formatat
    size_t formatted_message_size = strlen(msg->sender_ip) + 10 +
                                  strlen(msg->topic) + 3 +
                                  strlen(msg->data_type_str) + 3 +
                                  strlen(msg->cont_formatat) + 10;

    char *formatted_message_buffer = malloc(formatted_message_size);
    if (!formatted_message_buffer) return;
    //creeaza mesajul formatat
    int len_formatted = snprintf(formatted_message_buffer, formatted_message_size,
                              "%s:%u - %s - %s - %s",
                              msg->sender_ip, msg->sender_port, msg->topic,
                              msg->data_type_str, msg->cont_formatat);
    // array pt a urmari clientii care au primit mesajul
    bool *sent_status = calloc(MAX_CONNECTIONS + 50, sizeof(bool));
    if (!sent_status) {
        free(formatted_message_buffer);
        return;
    }
    //trimitem la toti clientii abonati la topic
    for (size_t i = 0; i < clients_map->size; i++) {
        Client *client = &clients_map->clients[i];
        if (client->is_occupied && client->connected && client->fd > 0 &&
            client->fd < MAX_CONNECTIONS + 50) {
            if (!sent_status[client->fd] && client_subscribed(client, msg->topic)) {
                if (send_all(client->fd, formatted_message_buffer, len_formatted + 1) <= 0) {
                    mark_client_disconnected(clients_map, client->fd);
                }
                sent_status[client->fd] = true;
            }
        }
    }

    free(sent_status);
    free(formatted_message_buffer);
}

void handle_subscribe(int client_fd, const char *topic, ClientsHashMap *clients_map) {
    Client *client = find_client_by_fd(clients_map, client_fd);
    if (!client) return;

    bool success = client_add_subscription(client, topic);
    char response[100];
    if (success) {
        snprintf(response, sizeof(response), "Subscribed to topic %s", topic);
    } else {
        snprintf(response, sizeof(response), "Failed to subscribe to topic %s", topic);
    }
    if (send_all(client_fd, response, strlen(response) + 1) <= 0) {
        mark_client_disconnected(clients_map, client_fd);
    }
}

void handle_unsubscribe(int client_fd, const char *topic, ClientsHashMap *clients_map) {
    Client *client = find_client_by_fd(clients_map, client_fd);
    if (!client) return;

    bool success = client_remove_subscription(client, topic);

    char response[100];
    if (success) {
        snprintf(response, sizeof(response), "Unsubscribed from topic %s", topic);
    } else {
        snprintf(response, sizeof(response), "Failed to unsubscribe from topic %s", topic);
    }

    if (send_all(client_fd, response, strlen(response) + 1) <= 0) {
        mark_client_disconnected(clients_map, client_fd);
    }
}

void process_tcp_message(int client_fd, const char *command_buffer, ClientsHashMap *clients_map) {
    char command_type[20] = {0};
    char topic_buffer[TOPIC_SIZE + 1] = {0};

    //parsam comanda si topicul
    int parsed = sscanf(command_buffer, "%19s %50s", command_type, topic_buffer);
    if (parsed < 2) {
        send_all(client_fd, "Invalid command format.", 24);
        return;
    }

    if (strcmp(command_type, "subscribe") == 0) {
        handle_subscribe(client_fd, topic_buffer, clients_map);
    } else if (strcmp(command_type, "unsubscribe") == 0) {
        handle_unsubscribe(client_fd, topic_buffer, clients_map);
    } else {
        send_all(client_fd, "Unknown command.", 16);
    }
}

bool authentification(int client_fd, struct sockaddr_in *client_addr, ClientsHashMap *clients_map) {
    char client_id[MAX_CLIENT_ID + 1] = {0};
    ssize_t bytes_received = recv(client_fd, client_id, MAX_CLIENT_ID, 0);

    if (bytes_received <= 0) return false;
    client_id[bytes_received] = '\0';
    // verifica daca id ul e deja in uz
    Client *existing = find_client_by_id(clients_map, client_id);
    if (existing && existing->connected) {
        printf("Client %s already connected.\n", client_id);
        send_all(client_fd, "ID already in use", 17);
        return false;
    }

    add_client_to_hashmap(clients_map, client_fd, client_id);

    char client_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr->sin_addr), client_ip_str, INET_ADDRSTRLEN);
    uint16_t client_port = ntohs(client_addr->sin_port);

    printf("New client %s connected from %s:%d.\n", client_id, client_ip_str, client_port);

    //confirmam conectarea
    if (send_all(client_fd, "Connected", 10) <= 0) {
        mark_client_disconnected(clients_map, client_fd);
        return false;
    }

    return true;
}

bool handle_stdin_event(struct pollfd *poll_fds, int num_fds) {
    char buffer[BUFLEN] = {0};

    if (fgets(buffer, sizeof(buffer) - 1, stdin) == NULL) {
        for (int j = 3; j < num_fds; j++) {
            if (poll_fds[j].fd > 0) close(poll_fds[j].fd);
        }
        return false;
    }
    // eliminam newline-ul
    char *newline = strchr(buffer, '\n');
    if (newline) {
        *newline = '\0';
    }
    //tratam comanda exit
    if (strcmp(buffer, "exit") == 0) {
        printf("Exit command received. Shutting down clients...\n");
        for (int j = 3; j < num_fds; j++) {
            if (poll_fds[j].fd > 0) close(poll_fds[j].fd);
        }
        return false;
    }

    return true;
}

int handle_new_connection(int tcp_sockfd, struct pollfd *poll_fds, int num_fds, ClientsHashMap *clients_map) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int newsockfd = accept(tcp_sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (newsockfd < 0) return 0;

    //dezactivam algoritmul Nagle
    int flag = 1;
    setsockopt(newsockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

    if (!authentification(newsockfd, &client_addr, clients_map)) {
        close(newsockfd);
        return 0;
    }

    //adaugam socketul in poll
    poll_fds[num_fds].fd = newsockfd;
    poll_fds[num_fds].events = POLLIN;
    poll_fds[num_fds].revents = 0;

    return 1;
}

void handle_udp_message(int udp_sockfd, ClientsHashMap *clients_map) {
    struct sockaddr_in udp_client_addr;
    socklen_t udp_client_len = sizeof(udp_client_addr);

    //aloc buffer dinamic pt UDP
    char *buffer = malloc(MAX_UDP_SIZE + 1);
    if (!buffer) return;

    //primim date udp
    ssize_t bytes_read = recvfrom(udp_sockfd, buffer, MAX_UDP_SIZE, 0,
                           (struct sockaddr *)&udp_client_addr, &udp_client_len);

    if (bytes_read < 0) {
        free(buffer);
        return;
    }

    message *msg = create_message();
    if (!msg) {
        free(buffer);
        return;
    }

    msg->type = MESSAGE_TYPE_UDP;

    //inf despre expeditor
    inet_ntop(AF_INET, &(udp_client_addr.sin_addr), msg->sender_ip, INET_ADDRSTRLEN);
    msg->sender_port = ntohs(udp_client_addr.sin_port);

    //extragem topicul(primii 50 de bytes)
    memcpy(msg->topic, buffer, TOPIC_SIZE);
    msg->topic[TOPIC_SIZE] = '\0';

    //extragem tipul de date
    msg->data_type = (uint8_t)buffer[TOPIC_SIZE];

    //calculam lungimea continutului
    msg->content_len = bytes_read - (TOPIC_SIZE + TYPE_SIZE);
    if (msg->content_len > MAX_CONTENT_SIZE) {
        msg->content_len = MAX_CONTENT_SIZE;
    } else if (msg->content_len < 0) {
        msg->content_len = 0;
    }

    //extrage continutul
    memcpy(msg->cont_brut, buffer + TOPIC_SIZE + TYPE_SIZE, msg->content_len);
    msg->cont_brut[msg->content_len] = '\0';

    process_udp_message(msg, clients_map);

    free_message(msg);
    free(buffer);
}

int handle_client_data(int client_fd, ClientsHashMap *clients_map) {
    char buffer[MAX_UDP_SIZE + 1] = {0};
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

    if (bytes_read <= 0) {
        mark_client_disconnected(clients_map, client_fd);
        close(client_fd);
        return -1;
    }

    buffer[bytes_read] = '\0';
    process_tcp_message(client_fd, buffer, clients_map);
    return 0;
}

void run_server(int tcp_sockfd, int udp_sockfd, ClientsHashMap *clients_map) {
    struct pollfd *poll_fds = malloc((MAX_CONNECTIONS + 3) * sizeof(struct pollfd));

    int num_fds = 0;
    memset(poll_fds, 0, sizeof(struct pollfd) * (MAX_CONNECTIONS + 3));

    //adaugam socketul tcp
    poll_fds[num_fds].fd = tcp_sockfd;
    poll_fds[num_fds].events = POLLIN;
    num_fds++;

    //adaugam socketul udp
    poll_fds[num_fds].fd = udp_sockfd;
    poll_fds[num_fds].events = POLLIN;
    num_fds++;

    //adaugam stdin
    poll_fds[num_fds].fd = STDIN_FILENO;
    poll_fds[num_fds].events = POLLIN;
    num_fds++;

    bool server_running = true;
    while (server_running) {
        int poll_count = poll(poll_fds, num_fds, -1);

        if (poll_count < 0) {
            if (errno == EINTR)
                continue;

            perror("poll failed");
            break;
        }
        //verificam fiecare descriptor pt evenimente
        for (int i = 0; i < num_fds; i++) {
            if (poll_fds[i].revents == 0)
                continue;

            int current_fd = poll_fds[i].fd;
            short current_events = poll_fds[i].revents;
            //eveniment pe stdin
            if (current_fd == STDIN_FILENO && (current_events & POLLIN)) {
                if (!handle_stdin_event(poll_fds, num_fds)) {
                    server_running = false;
                    break;
                }
            }
            //eveniment pe socketul tcp(conexiune noua)
            else if (current_fd == tcp_sockfd) {
                if (current_events & POLLIN) {
                    int new_fds = handle_new_connection(tcp_sockfd, poll_fds, num_fds, clients_map);
                    num_fds += new_fds;
                }
                else if (current_events & (POLLERR | POLLHUP | POLLNVAL)) {
                    server_running = false;
                    break;
                }
            }
            //eveniment pe socketul udp
            else if (current_fd == udp_sockfd && (current_events & POLLIN)) {
                handle_udp_message(udp_sockfd, clients_map);
            }
            // eveniment pe un client tcp
            else {
                if (current_events & POLLIN) {
                    if (handle_client_data(current_fd, clients_map) < 0) {
                        poll_fds[i] = poll_fds[--num_fds];
                        i--;
                    }
                }
                else if (current_events & (POLLERR | POLLHUP | POLLNVAL)) {
                    mark_client_disconnected(clients_map, current_fd);
                    close(current_fd);
                    poll_fds[i] = poll_fds[--num_fds];
                    i--;
                }
            }
        }
    }

    for (int j = 3; j < num_fds; j++) {
        if (poll_fds[j].fd > 0) {
            close(poll_fds[j].fd);
        }
    }
    free(poll_fds);
}

void cleanup_resources(int tcp_sockfd, int udp_sockfd, ClientsHashMap *clients_map) {
    if (tcp_sockfd >= 0) close(tcp_sockfd);
    if (udp_sockfd >= 0) close(udp_sockfd);
    if (clients_map != NULL) free_clients_hashmap(clients_map);
}

int init_server_sockets(int port, int *tcp_sockfd, int *udp_sockfd) {
    struct sockaddr_in server_addr;

    *tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    *udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (*tcp_sockfd < 0 || *udp_sockfd < 0) return -1;

    int optval = 1;
    setsockopt(*tcp_sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(*udp_sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons((uint16_t)port);

    if (bind(*tcp_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) return -2;
    if (bind(*udp_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) return -3;
    if (listen(*tcp_sockfd, MAX_CONNECTIONS) < 0) return -4;

    return 0;
}

int main(int argc, char *argv[]) {
    int result = 0;
    int tcp_sockfd = -1;
    int udp_sockfd = -1;
    ClientsHashMap *clients_map = NULL;

    setvbuf(stdout, NULL, _IONBF, BUFSIZ);
    setvbuf(stderr, NULL, _IONBF, BUFSIZ);

    if (argc != 2) {
        return 1;
    }

    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        return 1;
    }

    clients_map = create_clients_hashmap();
    if (!clients_map) return 1;

    result = init_server_sockets(port, &tcp_sockfd, &udp_sockfd);
    if (result < 0) {
        cleanup_resources(tcp_sockfd, udp_sockfd, clients_map);
        return 1;
    }

    run_server(tcp_sockfd, udp_sockfd, clients_map);
    cleanup_resources(tcp_sockfd, udp_sockfd, clients_map);

    return 0;
}