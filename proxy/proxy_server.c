#include "proxy_server.h"

static int server_fd;                                    // Zero by default
static struct client_info clients[MAX_CLIENTS + 1];      // All members will be zeroed by default
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; // Mutex initialization
static int port = PORT;                                  // Port initialization, default to 8080

int init_proxy(int argc, char const *argv[])
{
    struct sockaddr_in server_addr, client_addr; // Server and client addresses

    // Get the port
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
        goto cleanup;
    }

    // Set server socket option - reuse option
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
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
            continue;
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
            fprintf(stderr, "Max clients reached\n");
            if (socket_cleanup(client_fd) < 0)
            {
                fprintf(stderr, "Error socket cleanup server_fd at main: %s\n", strerror(errno));
            }
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
            if (socket_cleanup(client_fd) < 0)
            {
                fprintf(stderr, "Error socket cleanup server_fd at main: %s\n", strerror(errno));
            }
            goto cleanup;
        }
        else
        {
            if (pthread_detach(clients[i].thread) != 0)
            {
                perror("Failed to detach thread at main");
                if (socket_cleanup(client_fd) < 0)
                {
                    fprintf(stderr, "Error socket cleanup client_fd at main: %s\n", strerror(errno));
                }
                goto cleanup;
            }
        }
    }

    // Cleaning up
cleanup:
    // Release the listening port
    if (socket_cleanup(server_fd) < 0)
    {
        fprintf(stderr, "Error socket cleanup server_fd at main: %s\n", strerror(errno));
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
    char buffer[BUFFER_SIZE];
    char host[BUFFER_SIZE] = {0};
    char url[BUFFER_SIZE] = {0};
    char path[BUFFER_SIZE] = "/";
    char method[16] = {0};

    // Receive message from browser client
    ssize_t bytes_read = recv(client->socket, buffer, sizeof(buffer), 0);
    if (bytes_read < 0)
    {
        fprintf(stderr, "Failed to read data from client\n");
        goto cleanup;
    }
    buffer[bytes_read] = '\0'; // Ensure null termination

    // Parse clients request
    int port_connect = parse_request(buffer, method, url, host, path);
    if (port < 0)
    {
        fprintf(stderr, "Error parse request in handle client\n");
        goto cleanup;
    }

    /* Create the TCP socket for connecting to desired web server */

    if (strcmp(method, "CONNECT") == 0)
    {
        // Establish a connection to the target host for HTTPS
        int proxy_socket = connect_to_proxy(host, port_connect);
        if (proxy_socket < 0)
        {
            fprintf(stderr, "Failed to connect to (%s:%d) proxy for CONNECT request\n", host, port_connect);
            goto cleanup;
        }

        // Respond with "200 Connection Established"
        const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (send(client->socket, response, strlen(response), 0) <= 0)
        {
            fprintf(stderr, "Error sending response error to client\n");
            goto cleanup;
        }

        // Forward traffic between client and proxy
        forward_traffic(client->socket, proxy_socket);

        // Proxy socket
        if (socket_cleanup(proxy_socket) < 0)
        {
            fprintf(stderr, "Error socket cleanup proxy socket %d at handle client: %s\n", proxy_socket, strerror(errno));
        }

        goto cleanup;
    }
    else if (strcmp(method, "GET") == 0)
    {
        // Address initialization
        struct sockaddr_in proxy_addr;
        if (resolve_host(host, &proxy_addr) < 0)
        {
            fprintf(stderr, "Error resolve host in handle client\n");
            send_error_response(client->socket, "Failed to resolve host");
            goto cleanup;
        }

        // Create proxy socket
        int proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (proxy_socket < 0)
        {
            fprintf(stderr, "Error creating proxy socket at handle_client\n");
            goto cleanup;
        }

        // Connecting to the web servers socket
        if (connect(proxy_socket, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0)
        {
            fprintf(stderr, "Error at connect proxy socket at handle client\n");
            goto cleanup;
        }

        // Sanitize headers before forwarding
        sanitize_headers(buffer);

        // Handle proxys socket and clients socket communication
        if (handle_proxy_communication(proxy_socket, client->socket, buffer) < 0)
        {
            fprintf(stderr, "Error forwarding between proxy and client at handle client");
        }

        // Proxy socket
        if (socket_cleanup(proxy_socket) < 0)
        {
            fprintf(stderr, "Error socket cleanup proxy socket %d at handle client: %s\n", proxy_socket, strerror(errno));
        }
    }

    // Close connections
cleanup:
    // Client socket
    if (socket_cleanup(client->socket) < 0)
    {
        fprintf(stderr, "Error socket cleanup client socket %d at handle client: %s\n", client->socket, strerror(errno));
    }
    client->active = 0;

    return NULL;
}

// Return port (CONNECT), on successful execution return 0 (GET), if error value < 0
int parse_request(const char *data, char *method, char *url, char *host, char *path)
{
    // Create a mutable copy of data
    char data_copy[BUFFER_SIZE];
    strncpy(data_copy, data, BUFFER_SIZE - 1);
    data_copy[BUFFER_SIZE - 1] = '\0'; // Ensure null-termination

    // Get GET/CONNECT or send error to client
    char *pathname = strtok(data_copy, "\r\n");
    if (!pathname)
    {
        fprintf(stderr, "Invalid request: No valid request line\n");
        return -1;
    }
    if (sscanf(pathname, "%15s %s", method, url) != 2)
    {
        fprintf(stderr, "Invalid request in parse request: %s\n", pathname);
        return -1; // Invalid request
    }

    if (strcmp(method, "CONNECT") == 0)
    {
        printf("Recieved CONNECT request to %s\n", url);
        // Handle CONNECT method for HTTPS tunneling
        char *colon = strchr(url, ':');
        if (colon)
        {
            *colon = '\0'; // Split host and port
            strncpy(host, url, BUFFER_SIZE);
            host[BUFFER_SIZE - 1] = '\0'; // Ensure null termination
            int port = atoi(colon + 1);
            return port;
        }
        else
        {
            fprintf(stderr, "Invalid CONNECT URL\n");
            return -2; // Invalid CONNECT request
        }
    }
    else if (strcmp(method, "GET") == 0)
    {
        printf("Recieved GET request to %s\n", url);
        // Handle GET method for standard HTTP
        char *host_start = strstr(url, "http://");
        if (host_start)
        {
            host_start += strlen("http://"); // Skip "http://"
            char *path_start = strchr(host_start, '/');
            if (path_start)
            {
                strncpy(host, host_start, path_start - host_start);
                host[path_start - host_start] = '\0'; // Ensure null-termination
                strncpy(path, path_start, BUFFER_SIZE - 1);
                path[BUFFER_SIZE - 1] = '\0'; // Ensure null-termination
            }
            else
            {
                strncpy(path, path_start, BUFFER_SIZE - 1);
                host[BUFFER_SIZE - 1] = '\0'; // Ensure null-termination
                strcpy(path, "/");            // Default path
            }
            return 0; // Indicate successful GET parsing
        }
        else
        {
            fprintf(stderr, "Invalid host in parse request\n");
            return -2; // Invalid GET request
        }
    }
    else
    {
        fprintf(stderr, "Unsupported method: %s\n", method);
        return -1; // Unsupported HTTP method
    }
}

void sanitize_headers(char *buffer)
{
    printf("\nInitial Buffer:\n%s\n", buffer);

    // Remove X-Forwarded-For if present
    char *header_start = strstr(buffer, "X-Forwarded-For:");
    while (header_start)
    {
        char *header_end = strstr(header_start, "\r\n");
        if (header_end)
        {
            // Include the null terminator
            size_t remaining_length = strlen(header_end + 2) + 1;

            // Shift the rest of the buffer left to remove the header
            memmove(header_start, header_end + 2, remaining_length);
            header_start[remaining_length - 1] = '\0'; // Ensure null-termination
        }

        // Search for the next occurrence
        header_start = strstr(buffer, "X-Forwarded-For:");
    }

    // Remove Proxy-Connection if present
    header_start = strstr(buffer, "Proxy-Connection:");
    while (header_start)
    {
        char *header_end = strstr(header_start, "\r\n");
        if (header_end)
        {
            size_t remaining_length = strlen(header_end + 2) + 1; // Include the null terminator
            memmove(header_start, header_end + 2, remaining_length);
            header_start[remaining_length - 1] = '\0'; // Ensure null-termination
        }
        header_start = strstr(buffer, "Proxy-Connection:"); // Search for the next occurrence
    }

    // Replace other headers
    // replace_header(buffer, "User-Agent:", "AnonymousProxy/1.0"); // TODO: There issue

    printf("\nEnd Buffer\n%s\n", buffer);
}

void replace_header(char *buffer, const char *header_name, const char *replacement)
{
    char *header_start = strstr(buffer, header_name);
    if (!header_start)
    {
        // Header not found
        return;
    }

    char *header_end = strstr(buffer, "\r\n");
    if (!header_end)
    {
        // Malformed buffer, no end of header
        fprintf(stderr, "Error: Malformed buffer in replace header\n");
        return;
    }

    // Calculate space for the new header
    size_t header_name_length = strlen(header_name);
    size_t new_header_length = header_name_length + strlen(replacement) + 2; // ": " + value
    size_t remaining_length = strlen(header_end + 2) + 1;                    // Include null terminator

    if ((header_start - buffer) + new_header_length + remaining_length > BUFFER_SIZE)
    {
        fprintf(stderr, "Error: Buffer overflow risk in replace_header\n");
        return;
    }

    // Shift buffer contents after the header to accommodate the new value
    memmove(header_start + new_header_length, header_end + 2, remaining_length);

    // Write the new header
    snprintf(header_start, new_header_length + 1, "%s %s", header_name, replacement);
}

int connect_to_proxy(const char *host, int port)
{
    struct addrinfo hints, *res, *ptr;
    int proxy_socket;
    char port_str[6]; // Max port length is 5 digits + null terminator

    // Convert port to string
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // Use IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP socket

    // Resolve host and port
    if (getaddrinfo(host, port_str, &hints, &res) != 0)
    {
        perror("getaddrinfo failed");
        return -1;
    }

    // Iterate through the results to create a socket and connect
    for (ptr = res; ptr != NULL; ptr = ptr->ai_next)
    {
        proxy_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (proxy_socket == -1)
        {
            continue;
        }

        if (connect(proxy_socket, ptr->ai_addr, ptr->ai_addrlen) == 0)
        {
            break; // Successfully connected
        }

        // Release the listening port
        if (socket_cleanup(proxy_socket) < 0)
        {
            fprintf(stderr, "Error socket cleanup proxy socket at connect to proxy: %s\n", strerror(errno));
        }
    }

    // Clean up the addrinfo structure
    freeaddrinfo(res);

    if (ptr == NULL)
    {
        fprintf(stderr, "Failed to connect to proxy\n");
        return -1;
    }

    // Return the connected socket
    return proxy_socket;
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
    proxy_addr->sin_port = htons(80);
    memcpy(&proxy_addr->sin_addr.s_addr, proxy->h_addr_list[0], proxy->h_length);
    return 0;
}

int handle_proxy_communication(int proxy_socket, int client_socket, const char *request)
{
    // Forward request to server
    if (send(proxy_socket, request, strlen(request), 0) < 0)
    {
        fprintf(stderr, "Error forwarding request to server\n");
        return -1;
    }

    // Forward response to client
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = recv(proxy_socket, buffer, sizeof(buffer), 0)) > 0)
    {
        if (send(client_socket, buffer, bytes_read, 0) < 0)
        {
            fprintf(stderr, "Error forwarding response to client\n");
            return -1;
        }
    }
    if (bytes_read < 0)
    {
        fprintf(stderr, "Error reading from server\n");
        return -1;
    }

    return 0;
}

void forward_traffic(int client_socket, int proxy_socket)
{
    char buffer[BUFFER_SIZE];
    fd_set fds;
    int max_fd = (client_socket > proxy_socket) ? client_socket : proxy_socket;

    struct timeval timeout;
    timeout.tv_sec = 5; // 5-second timeout
    timeout.tv_usec = 0;

    while (1)
    {
        FD_ZERO(&fds);
        FD_SET(client_socket, &fds);
        FD_SET(proxy_socket, &fds);

        // Wait for activity on either socket
        if (select(max_fd + 1, &fds, NULL, NULL, &timeout) < 0)
        {
            fprintf(stderr, "Select error at forward traffic\n");
            break;
        }

        // Data from client to proxy
        if (FD_ISSET(client_socket, &fds))
        {
            int bytes = recv(client_socket, buffer, BUFFER_SIZE, 0);
            if (bytes <= 0) // Client closed connection
            {
                if (bytes == 0)
                {
                    fprintf(stderr, "Proxy closed the connection\n");
                }
                else
                {
                    perror("Failed to read data from proxy at forward traffic");
                }
                break;
            }

            if (send(proxy_socket, buffer, bytes, 0) <= 0)
            {
                fprintf(stderr, "Error sending data from client to proxy\n");
                break;
            }
        }

        // Data from proxy to client
        if (FD_ISSET(proxy_socket, &fds))
        {
            int bytes = recv(proxy_socket, buffer, BUFFER_SIZE, 0);
            if (bytes <= 0) // Proxy closed connection
            {
                fprintf(stderr, "Failed to read data from proxy at forward traffic\n");
                break;
            }
            if (send(client_socket, buffer, bytes, 0) <= 0)
            {
                fprintf(stderr, "Error sending data from proxy to client\n");
                break;
            }
        }
    }
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

    if (sigaction(signal, &sa, NULL) < 0)
    {
        fprintf(stderr, "Error sigaction failed at setup_signal for signal %d: %s\n", signal, strerror(errno));

        // If sigaction fails abort()
        abort();
    }
}

void handle_shutdown(int signo, siginfo_t *info, void *context)
{
    (void)context;

    printf("\nCaught signal %d (SIGINT). Shutting down gracefully...\n", signo);

    if (info != NULL)
    {
        printf("Signal sent by process: %d\n", info->si_pid);
        printf("Signal sent by user: %d\n", info->si_uid);

        if (signo == SIGINT)
        {
            printf("This is an interrupt signal from the keyboard.\n");
        }
    }

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
                if (socket_cleanup(clients[i].socket) < 0)
                {
                    fprintf(stderr, "Error socket cleanup client socket %d at handle shutdown: %s\n", i, strerror(errno));
                }
                clients[i].socket = 0;
            }
            else
            {
                fprintf(stderr, "Invalid socket descriptor %d at handle shutdown\n", clients[i].socket);
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
    if (socket_cleanup(server_fd) < 0)
    {
        fprintf(stderr, "Error socket cleanup server socket at handle shutdown: %s\n", strerror(errno));
    }

    // Destroy mutex
    if (pthread_mutex_destroy(&lock) != 0)
    {
        fprintf(stderr, "Error pthread_mutex_destroy failed\n");
    }

    exit(EXIT_SUCCESS);
}