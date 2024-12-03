#include "proxy_server.h"

static jmp_buf jump_env;                                 // For cleanup jump
static int server_fd;                                    // Zero by default
static struct client_info clients[MAX_CLIENTS + 1];      // All members will be zeroed by default
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; // Mutex initialization

int init_proxy(int argc, char const *argv[])
{
    struct sockaddr_in server_addr, client_addr; // Server and client addresses

    // Get the port
    int port = PORT;
    if (argc == 2)
    {
        port = atoi(argv[1]);
    }

    // Configure signal handlers
    setup_signal(SIGINT, handle_shutdown); // Handle Ctrl+C

    // Create server socket TCP
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("Socket error at main");
        if (pthread_mutex_destroy(&lock) != 0)
        {
            fprintf(stderr, "Error pthread_mutex_destroy failed\n");
        }
        exit(EXIT_FAILURE);
    }

    // Set server socket option - reuse option
    int REUSE_OPTION = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&REUSE_OPTION, sizeof(REUSE_OPTION)) < 0)
    {
        perror("Set socket option (SO_REUSEADDR) error at main");
        goto cleanup;
    }

    // Set server address and port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket to the address and port
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Bind error at main");
        goto cleanup;
    }

    // Listen for incoming connections
    if (listen(server_fd, MAX_CLIENTS) < 0)
    {
        perror("Lesten error at main");
        goto cleanup;
    }

    printf("Proxy server listening on port %d\n", port);

    // Main clients loop
    while (1)
    {
        memset(&client_addr, 0, sizeof(client_addr));
        socklen_t client_addr_len = sizeof(client_addr);

        // Add client to server
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd < 0)
        {
            perror("Accept error at main");
            goto cleanup;
        }

        // Add the client socket to the list of clients
        int i = 0;
        pthread_mutex_lock(&lock);
        for (i = 0; i <= MAX_CLIENTS; ++i)
        {
            if (clients[i].socket == 0)
            {
                clients[i].socket = client_fd;
                clients[i].active = 1;
                break;
            }
        }
        pthread_mutex_unlock(&lock);

        // If no slot found for the new client
        if (i > MAX_CLIENTS)
        {
            const char *msg = "Server is full, try againg later\n";
            if (write(client_fd, msg, strlen(msg)) <= 0)
            {
                fprintf(stderr, "Error sending no slot found for the new client to client %d:\n", i);
            }
            if (shutdown(client_fd, SHUT_RDWR) < 0)
            {
                fprintf(stderr, "Error shutdown server_fd at main: %s\n", strerror(errno));
            }
            if (close(client_fd) < 0)
            {
                fprintf(stderr, "Error closing server socket at slot not found for the new client: %s\n", strerror(errno));
            }

            // TODO: Handle rest of client normally
            continue;
        }

        // Print clients ip and port
        char ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_addr, INET_ADDRSTRLEN);
        printf("Client is connected with port: %d and ip: %s\n", ntohs(client_addr.sin_port), ip_addr);

        // Create a thread for each client
        if (pthread_create(&clients[i].thread, NULL, handle_client, &clients[i]) != 0)
        {
            perror("Failed to create thread at main");
            if (shutdown(client_fd, SHUT_RDWR) < 0)
            {
                fprintf(stderr, "Error shutdown server_fd at main: %s\n", strerror(errno));
            }
            if (close(client_fd))
            {
                fprintf(stderr, "Error closing client_fd at main: %s\n", strerror(errno));
            }
            goto cleanup;
        }
        else
        {
            if (pthread_detach(clients[i].thread) != 0)
            {
                perror("Failed to detach thread at main");
                if (shutdown(client_fd, SHUT_RDWR) < 0)
                {
                    fprintf(stderr, "Error shutdown client_fd at main: %s\n", strerror(errno));
                }
                if (close(client_fd))
                {
                    fprintf(stderr, "Error closing client_fd at main: %s\n", strerror(errno));
                }
                goto cleanup;
            }
        }
    }

cleanup:
    // Release the listening port
    if (shutdown(server_fd, SHUT_RDWR) < 0)
    {
        fprintf(stderr, "Error shutdown server_fd at main: %s\n", strerror(errno));
    }
    if (close(server_fd) < 0)
    {
        fprintf(stderr, "Error closing server_fd at main: %s\n", strerror(errno));
    }

    // Destroy mutex
    if (pthread_mutex_destroy(&lock) != 0)
    {
        fprintf(stderr, "Error pthread_mutex_destroy failed\n");
    }

    return 0;
}

void *handle_client(void *arg)
{
    client_info *client = (client_info *)arg;
    char data[BUFFER_SIZE];
    char host[BUFFER_SIZE] = {0};
    char url[BUFFER_SIZE] = {0};
    char path[BUFFER_SIZE] = "/";
    char method[16] = {0};

    // Receive message from browser client
    ssize_t bytes_read = recv(client->socket, data, sizeof(data), 0);
    if (bytes_read < 0)
    {
        perror("Error recv at handle client");
        goto cleanup_1;
    }

    // Parse clients request
    if (parse_request(data, method, url, host, path) < 0)
    {
        fprintf(stderr, "Error parse request in handle client\n");
        send_error_response(client->socket, "Invalid request or host");
        goto cleanup_1;
    }

    /* Create the TCP socket for connecting to desired web server */

    // Address initialization
    struct sockaddr_in proxy_addr;
    if (resolve_host(host, &proxy_addr) < 0)
    {
        fprintf(stderr, "Error resolve host in handle client\n");
        send_error_response(client->socket, "Failed to resolve host");
        goto cleanup_1;
    }

    // Create proxy socket
    int proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_socket < 0)
    {
        fprintf(stderr, "Error creating proxy socket at handle_client\n");
        goto cleanup_1;
    }

    // Connecting to the web servers socket
    if (connect(proxy_socket, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0)
    {
        fprintf(stderr, "Error at connect proxy socket at handle client\n");
        goto cleanup_2;
    }

    // Handle proxys socket and clients socket communication 
    if (handle_proxy_communication(proxy_socket, client->socket, data) < 0)
    {
        fprintf(stderr, "Error forwarding between proxy and client at handle client");
    }

    // Close connections
cleanup_2:
    // Proxy socket
    if (socket_cleanup(proxy_socket) < 0)
    {
        fprintf(stderr, "Error socket cleanup proxy socket %d at handle_client: %s\n", proxy_socket, strerror(errno));
    }
cleanup_1:
    // Client socket
    if (socket_cleanup(client->socket) < 0)
    {
        fprintf(stderr, "Error socket cleanup client socket %d at handle_client: %s\n", client->socket, strerror(errno));
    }

    client->active = 0;

    return NULL;
}

int parse_request(const char *data, char *method, char *url, char *host, char *path)
{
    // Create a mutable copy of data
    char data_copy[BUFFER_SIZE];
    strncpy(data_copy, data, BUFFER_SIZE - 1);
    data_copy[BUFFER_SIZE - 1] = '\0'; // Ensure null-termination

    // Get GET or send error to client
    char *pathname = strtok(data_copy, "\r\n");
    if (sscanf(pathname, "%15s %s", method, url) != 2 || strcmp(method, "GET") != 0)
    {
        fprintf(stderr, "Invalid request at parse request\n");
        return -1; // Invalid request
    }

    // Separate the hostname from the path
    char *host_start = strstr(url, "http://");
    if (host_start)
    {
        host_start += strlen("http://"); // Skip "http://"
        char *path_start = strchr(host_start, '/');
        if (path_start)
        {
            strncpy(host, host_start, path_start - host_start);
            host[path_start - host_start] = '\0';
            strncpy(path, path_start, BUFFER_SIZE - 1);
        }
        else
        {
            strncpy(path, path_start, BUFFER_SIZE - 1);
            host[BUFFER_SIZE - 1] = '\0'; // Ensure null-termination
            strcpy(path, "/"); // Default path
        }
    }
    else
    {
        fprintf(stderr, "Invalid host at parse request\n");
        return -2; // Invalid host
    }
    return 0;
}

int resolve_host(const char *host, struct sockaddr_in *proxy_addr)
{
    struct hostent *proxy = gethostbyname(host);
    if (proxy == NULL)
    {
        return -1;
    }
    memset(proxy_addr, 0, sizeof(*proxy_addr));
    proxy_addr->sin_family = AF_INET;
    proxy_addr->sin_port = htons(80); // TODO: Make port configurable
    memcpy(&proxy_addr->sin_addr.s_addr, proxy->h_addr_list[0], proxy->h_length);
    return 0;
}

int forward_request_to_server(const char *request, int proxy_socket)
{
    ssize_t sent = send(proxy_socket, request, strlen(request), 0);
    if (sent < 0)
    {
        perror("Error sending request to server");
        return -1;
    }

    return 0;
}

int forward_response_to_client(int proxy_socket, int client_socket)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = recv(proxy_socket, buffer, sizeof(buffer), 0)) > 0)
    {
        if (send(client_socket, buffer, bytes_read, 0) < 0)
        {
            perror("Error forwarding response to client");
            return -1;
        }
    }
    if (bytes_read < 0)
    {
        perror("Error reading from server");
        return -1;
    }
    return 0;
}

int handle_proxy_communication(int proxy_socket, int client_socket, const char *request)
{
    // Sending the HTTP request of the client to the web server
    if (forward_request_to_server(request, proxy_socket) < 0)
    {
        fprintf(stderr, "Error forward request to server at handle proxy communication");
        return -1;
    }

    // Sending the HTTP response form the web server to the client
    if (forward_response_to_client(proxy_socket, client_socket) < 0)
    {
        fprintf(stderr, "Error forward response from server to client at handle proxy communication\n");
        return -2;
    }
    return 0;
}

int socket_cleanup(int socket)
{
    if (shutdown(socket, SHUT_RDWR) < 0)
    {
        fprintf(stderr, "Error shutdown client socket %d at socket cleanup: %s\n", socket, strerror(errno));
        return -1;
    }
    if (close(socket) < 0)
    {
        fprintf(stderr, "Error closing client socket %d at socket cleanup: %s\n", socket, strerror(errno));
        return -1;
    }
    return 0;
}

void send_error_response(int client_socket, const char *message)
{
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "HTTP/1.1 400 Bad Request\r\n\r\n%s\n", message);
    if (write(client_socket, buffer, strlen(buffer)) < 0)
    {
        fprintf(stderr, "Error send error response to %d at send error response: %s\n", client_socket, strerror(errno));
    }
}

void setup_signal(int signal, void (*handler)(int, siginfo_t *, void *))
{
    struct sigaction sa;
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (setjmp(jump_env) != 0)
    {
        // Jumped back here after signal handling or error
        printf("Signal handling failed or interrupted, cleaning up...\n");
        exit(EXIT_FAILURE); // Or do any other cleanup
    }

    if (sigaction(signal, &sa, NULL) < 0)
    {
        fprintf(stderr, "Error sigaction failed at setup_signal for signal %d: %s\n", signal, strerror(errno));

        // If sigaction fails, jump to cleanup
        longjmp(jump_env, 1);
    }
}

void handle_shutdown(int signo, siginfo_t *info, void *context)
{
    (void)context;

    printf("Caught signal %d (SIGINT). Shutting down gracefully...\n", signo);

    if (info != NULL)
    {
        printf("Signal sent by process: %d\n", info->si_pid);
        printf("Signal sent by user: %d\n", info->si_uid);

        if (signo == SIGINT)
        {
            printf("This is an interrupt signal from the keyboard.\n");
        }
    }

    // Long jump to here (trigger cleanup)
    longjmp(jump_env, 1);

    // Shutdown entire system
    pthread_mutex_lock(&lock);
    for (int i = 0; i <= MAX_CLIENTS; ++i)
    {
        if (clients[i].socket > 0)
        {
            // Check if the socket is still valid
            if (fcntl(clients[i].socket, F_GETFD) != -1 || errno != EBADF)
            {
                // Close the client socket
                if (shutdown(clients[i].socket, SHUT_RDWR) < 0)
                {
                    fprintf(stderr, "Error shutdown client socket %d at handle_client: %s\n", i, strerror(errno));
                }
                if (close(clients[i].socket) < 0)
                {
                    fprintf(stderr, "Error closing client socket %d at handle_shutdown: %s\n", i, strerror(errno));
                }
                clients[i].socket = 0;
            }
            else
            {
                fprintf(stderr, "Invalid socket descriptor %d at handle_shutdown\n", clients[i].socket);
                clients[i].socket = 0;
            }
        }
    }
    pthread_mutex_unlock(&lock);

    // Join active threads
    for (int i = 0; i <= MAX_CLIENTS; ++i)
    {
        if (clients[i].active)
        {
            int err_pthread = pthread_cancel(clients[i].thread);
            if (err_pthread != 0)
            {
                fprintf(stderr, "Error joining thread %d, error = %d\n", i, err_pthread);
            }
            clients[i].active = 0;
        }
    }

    // Release the listening port
    if (shutdown(server_fd, SHUT_RDWR) < 0)
    {
        fprintf(stderr, "Error shutdown server socket at handle_client: %s\n", strerror(errno));
    }
    if (close(server_fd) < 0)
    {
        fprintf(stderr, "Error closing server_fd at main: %s\n", strerror(errno));
    }

    // Destroy mutex
    if (pthread_mutex_destroy(&lock) != 0)
    {
        fprintf(stderr, "Error pthread_mutex_destroy failed\n");
    }

    exit(EXIT_SUCCESS);
}