#include "tcp_sock.h"

// #include "log.h"

#include <stdlib.h>
#include <unistd.h>

char filename[100];

// tcp server application, listens to port (specified by arg) and serves only one
// connection request

