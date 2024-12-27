#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// #include <openssl/ssl.h>
// #include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 10

typedef struct client_info client_info;
typedef struct cache_obj cache_obj;

struct client_info
{
    int active;
    int socket;
    pthread_t thread;
    cache_obj *cache;
};

int init_proxy(int argc, char const *argv[]);
void *handle_client(void *arg);
int parse_request(const char *data, char *method, char *url, char *host, char *path);
void sanitize_headers(char *buffer);
void replace_header(char *buffer, const char *header_name, const char *replacement);
int resolve_host(const char *host, struct sockaddr_in *proxy_addr);
int connect_to_proxy(const char *host, int port);
int handle_proxy_communication(int proxy_socket, int client_socket, const char *requset);
int socket_cleanup(int socket);
void forward_traffic(int client_socket, int proxy_socket);
void send_error_response(int client_socket, const char *message);
void setup_signal(int signal, void (*handler)(int, siginfo_t *, void *));
void handle_shutdown(int signo, siginfo_t *info, void *context);

#endif // PROXY_SERVER_H