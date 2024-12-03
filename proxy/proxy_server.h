#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <errno.h>
#include <setjmp.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
int resolve_host(const char *host, struct sockaddr_in *proxy_addr);
int forward_request_to_server(const char *request, int proxy_socket);
int forward_response_to_client(int proxy_socket, int client_socket);
int handle_proxy_communication(int proxy_socket, int client_socket, const char *request);
int socket_cleanup(int socket);
void send_error_response(int client_socket, const char *message);
void setup_signal(int signal, void (*handler)(int, siginfo_t *, void *));
void handle_shutdown(int signo, siginfo_t *info, void *context);
#endif // PROXY_SERVER_H