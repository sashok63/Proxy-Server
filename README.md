# Proxy
Proxy Server with pthreads for handling HTTP requests

## Still in work
* Support for HTTPS requests

## Building 
```bash
make
```

## Usage
```bash

./server <port> - on Linux to open the server on port

curl -x http://localhost:<port> http://<url> - send request
```

### Server
Ctrl + C -  shutdown server
