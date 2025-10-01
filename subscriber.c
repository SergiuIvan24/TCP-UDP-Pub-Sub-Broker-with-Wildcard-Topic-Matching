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
#include "common_structs.h"

#define BUFLEN 2048

// Buffer pentru primirea mesajelor de la server
typedef struct {
    char data[BUFLEN * 2];  // Dimensiune dubla pentru mesaje concatenate
    size_t current_size;    // Marimea curenta a datelor valide
} ReceiveBuffer;

// Buffer pentru comenzile utilizatorului
typedef struct {
    char data[BUFLEN];
} CommandBuffer;

int send_all(int sockfd, const void *buffer, size_t len) {
    if (len == 0) return 0;

    ssize_t bytes_sent = send(sockfd, buffer, len, 0);
    if (bytes_sent <= 0) return bytes_sent;

    if ((size_t)bytes_sent == len) return bytes_sent;

    ssize_t remaining_result = send_all(sockfd, (const char *)buffer + bytes_sent, len - bytes_sent);
    if (remaining_result < 0) return remaining_result;

    return bytes_sent + remaining_result;
}

int connect_to_server(const char *server_ip, int server_port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    //dezactivam algoritmul Nagle
    int flag = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);

    // converteste adresa IP
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        close(sockfd);
        return -1;
    }
    // stabilim conexiunea
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect failed");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

void init_receive_buffer(ReceiveBuffer *rb) {
    memset(rb->data, 0, sizeof(rb->data));
    rb->current_size = 0;
}

void init_command_buffer(CommandBuffer *cb) {
    memset(cb->data, 0, sizeof(cb->data));
}
// autentifica clientul la server
bool authenticate_client(int sockfd, const char *client_id, ReceiveBuffer *rb) {
    // trimitem ID-ul clientului
    if (send(sockfd, client_id, strlen(client_id), 0) <= 0) {
        perror("Client ID not sent");
        return false;
    }

    // asteptam confirmarea de la server
    memset(rb->data, 0, sizeof(rb->data));
    ssize_t bytes_read = recv(sockfd, rb->data, BUFLEN - 1, 0);
    if (bytes_read <= 0) {
        perror("Connection not confirmed");
        return false;
    }

    rb->data[bytes_read] = '\0';
    if (strcmp(rb->data, "Connected") != 0) {
        fprintf(stderr, "Server error: %s\n", rb->data);
        return false;
    }

    return true;
}

bool process_stdin_command(int sockfd, CommandBuffer *cb) {
    if (fgets(cb->data, BUFLEN - 1, stdin) == NULL) {
        return false;
    }
    //eliminam newline
    char *newline = strchr(cb->data, '\n');
    if (newline) {
        *newline = '\0';
    }

    // trateaza comanda exit
    if (strcmp(cb->data, "exit") == 0) {
        printf("Disconnecting from server...\n");
        return false;
    }

    //parsam si trimitem comenzile valide
    char cmd[20] = {0};
    char topic[TOPIC_SIZE + 1] = {0};
    int parsed = sscanf(cb->data, "%19s %50s", cmd, topic);

    if (parsed == 2 && (strcmp(cmd, "subscribe") == 0 || strcmp(cmd, "unsubscribe") == 0)) {
        int send_result = send_all(sockfd, cb->data, strlen(cb->data) + 1);
        if (send_result <= 0) {
            perror("Failed to send command");
            return false;
        }
    }

    return true;
}

bool process_server_message(int sockfd, ReceiveBuffer *rb) {
    //citim date in buffer
    ssize_t bytes_read = recv(sockfd, rb->data + rb->current_size,
                             sizeof(rb->data) - rb->current_size - 1, 0);

    if (bytes_read <= 0) {
        if (bytes_read < 0) perror("Receive failed");
        else printf("Server closed connection.\n");
        return false;
    }

    rb->current_size += bytes_read;
    rb->data[rb->current_size] = '\0';

    char *msg_start = rb->data;
    char *null_pos;
    size_t processed = 0;

    while ((null_pos = strchr(msg_start, '\0')) && null_pos < rb->data + rb->current_size) {
        printf("%s\n", msg_start);
        size_t msg_len = null_pos - msg_start + 1;
        msg_start += msg_len;
        processed += msg_len;
    }

    //mut datele ramase la inceputul buffer-ului
    if (processed > 0) {
        rb->current_size -= processed;
        if (rb->current_size > 0)
            memmove(rb->data, msg_start, rb->current_size);
        rb->data[rb->current_size] = '\0';
    }

    return true;
}

void run_client(int sockfd, const char *client_id) {
    struct pollfd poll_fds[2];
    ReceiveBuffer receive_buffer;
    CommandBuffer command_buffer;

    init_receive_buffer(&receive_buffer);
    init_command_buffer(&command_buffer);

    poll_fds[0].fd = STDIN_FILENO;
    poll_fds[0].events = POLLIN;
    poll_fds[1].fd = sockfd;
    poll_fds[1].events = POLLIN;

    if (!authenticate_client(sockfd, client_id, &receive_buffer)) {
        return;
    }

    init_receive_buffer(&receive_buffer);

    while (1) {
        if (poll(poll_fds, 2, -1) < 0) {
            break;
        }

        if (poll_fds[0].revents & POLLIN) {
            if (!process_stdin_command(sockfd, &command_buffer)) {
                break;
            }
        }

        if (poll_fds[1].revents & POLLIN) {
            if (!process_server_message(sockfd, &receive_buffer)) {
                break;
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        return 1;
    }

    setvbuf(stdout, NULL, _IONBF, BUFSIZ);
    setvbuf(stderr, NULL, _IONBF, BUFSIZ);

    if (strlen(argv[1]) > MAX_CLIENT_ID) {
        return 1;
    }

    int port = atoi(argv[3]);
    if (port <= 0 || port > 65535) {
        return 1;
    }

    int sockfd = connect_to_server(argv[2], port);
    if (sockfd < 0) {
        return 1;
    }

    run_client(sockfd, argv[1]);
    close(sockfd);
    return 0;
}